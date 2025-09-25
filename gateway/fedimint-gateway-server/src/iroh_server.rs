use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::anyhow;
use axum::{Extension, Json};
use fedimint_core::net::iroh::build_iroh_endpoint;
use fedimint_core::task::TaskGroup;
use fedimint_gateway_common::{FEDIMINT_GATEWAY_ALPN, IrohGatewayRequest, IrohGatewayResponse};
use fedimint_logging::LOG_GATEWAY;
use iroh::endpoint::Incoming;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::json;
use tracing::info;

use crate::Gateway;
use crate::error::{GatewayError, PublicGatewayError};

type GetHandler = Box<
    dyn Fn(
            Extension<Arc<Gateway>>,
        )
            -> Pin<Box<dyn Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send>>
        + Send
        + Sync,
>;

type PostHandler = Box<
    dyn Fn(
            Extension<Arc<Gateway>>,
            serde_json::Value,
        )
            -> Pin<Box<dyn Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send>>
        + Send
        + Sync,
>;

fn make_get_handler<F, Fut>(f: F) -> GetHandler
where
    F: Fn(Extension<Arc<Gateway>>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    Box::new(move |gateway: Extension<Arc<Gateway>>| {
        let f = f.clone();
        Box::pin(async move {
            let res = f(gateway).await?;
            Ok(res)
        })
    })
}

fn make_post_handler<P, F, Fut>(f: F) -> PostHandler
where
    P: DeserializeOwned + Send + 'static,
    F: Fn(Extension<Arc<Gateway>>, Json<P>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    Box::new(
        move |gateway: Extension<Arc<Gateway>>, value: serde_json::Value| {
            let f = f.clone();
            Box::pin(async move {
                let payload: P = serde_json::from_value(value)
                    .map_err(|e| PublicGatewayError::Unexpected(anyhow!(e.to_string())))?;
                let res = f(gateway, Json(payload)).await?;
                Ok(res)
            })
        },
    )
}

pub struct Handlers {
    get_handlers: BTreeMap<String, GetHandler>,
    post_handlers: BTreeMap<String, PostHandler>,
    authenticated_routes: BTreeSet<String>,
}

impl Handlers {
    pub fn new() -> Self {
        Handlers {
            get_handlers: BTreeMap::new(),
            post_handlers: BTreeMap::new(),
            authenticated_routes: BTreeSet::new(),
        }
    }

    pub fn add_handler<F, Fut>(&mut self, route: &str, f: F, is_authenticated: bool)
    where
        F: Fn(Extension<Arc<Gateway>>) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
    {
        if is_authenticated {
            self.authenticated_routes.insert(route.to_string());
        }
        self.get_handlers
            .insert(route.to_string(), make_get_handler(f));
    }

    pub fn get_handler(&self, route: &str) -> Option<&GetHandler> {
        self.get_handlers.get(route)
    }

    pub fn add_handler_with_payload<P, F, Fut>(&mut self, route: &str, f: F, is_authenticated: bool)
    where
        P: DeserializeOwned + Send + 'static,
        F: Fn(Extension<Arc<Gateway>>, Json<P>) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
    {
        if is_authenticated {
            self.authenticated_routes.insert(route.to_string());
        }

        self.post_handlers
            .insert(route.to_string(), make_post_handler(f));
    }

    pub fn get_handler_with_payload(&self, route: &str) -> Option<&PostHandler> {
        self.post_handlers.get(route)
    }

    pub fn is_authenticated(&self, route: &str) -> bool {
        self.authenticated_routes.contains(route)
    }
}

pub async fn start_iroh_endpoint(
    gateway: &Arc<Gateway>,
    task_group: TaskGroup,
    handlers: Arc<Handlers>,
) -> anyhow::Result<()> {
    info!("Building Iroh Endpoint...");
    let iroh_endpoint = build_iroh_endpoint(
        gateway.iroh_sk.clone(),
        gateway.iroh_listen,
        gateway.iroh_dns.clone(),
        gateway.iroh_relays.clone(),
        FEDIMINT_GATEWAY_ALPN,
    )
    .await?;
    let gw_clone = gateway.clone();
    let tg_clone = task_group.clone();
    let handlers_clone = handlers.clone();
    info!("Spawning accept loop...");
    task_group.spawn("Gateway Iroh", |_| async move {
        loop {
            match iroh_endpoint.accept().await {
                Some(incoming) => {
                    info!("Accepted new connection. Spawning handler...");
                    tg_clone.spawn_cancellable_silent(
                        "handle endpoint accept",
                        handle_incoming_iroh_request(
                            incoming,
                            gw_clone.clone(),
                            handlers_clone.clone(),
                        ),
                    );
                }
                None => {
                    break;
                }
            }
        }
    });

    info!(target: LOG_GATEWAY, "Successfully started iroh endpoint");

    Ok(())
}

async fn handle_incoming_iroh_request(
    incoming: Incoming,
    gateway: Arc<Gateway>,
    handlers: Arc<Handlers>,
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    let remote_node_id = &connection.remote_node_id()?;
    info!(%remote_node_id, "Handler received connection");
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let request = recv.read_to_end(100_000).await?;
        let request = serde_json::from_slice::<IrohGatewayRequest>(&request)?;

        let (status, body) = handle_request(&request, gateway.clone(), handlers.clone()).await?;

        let response = IrohGatewayResponse {
            status: status.as_u16(),
            body: body.0,
        };
        let response = serde_json::to_vec(&response)?;

        send.write_all(&response).await?;
        send.finish()?;
    }
    Ok(())
}

async fn handle_request(
    request: &IrohGatewayRequest,
    gateway: Arc<Gateway>,
    handlers: Arc<Handlers>,
) -> anyhow::Result<(StatusCode, Json<serde_json::Value>)> {
    if handlers.is_authenticated(&request.route) {
        if let Err(_) = iroh_verify_password(gateway.clone(), request) {
            return Ok((StatusCode::UNAUTHORIZED, Json(json!(()))));
        }
    }

    let (status, body) = match &request.params {
        Some(params) => {
            if let Some(handler) = handlers.get_handler_with_payload(&request.route) {
                (
                    StatusCode::OK,
                    handler(Extension(gateway), params.clone()).await?,
                )
            } else {
                return Err(anyhow!("Iroh handler received request with unknown route"));
            }
        }
        None => {
            if let Some(handler) = handlers.get_handler(&request.route) {
                (StatusCode::OK, handler(Extension(gateway)).await?)
            } else {
                return Err(anyhow!("Iroh handler received request with unknown route"));
            }
        }
    };

    Ok((status, body))
}

fn iroh_verify_password(gateway: Arc<Gateway>, request: &IrohGatewayRequest) -> anyhow::Result<()> {
    if let Some(password) = request.password.as_ref() {
        if bcrypt::verify(password, &gateway.bcrypt_password_hash.to_string())? {
            return Ok(());
        }
    }

    Err(anyhow!("Invalid password"))
}
