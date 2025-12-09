use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::anyhow;
use axum::extract::{Path, Query};
use axum::{Extension, Json};
use bitcoin::hashes::sha256;
use fedimint_core::module::{FEDIMINT_GATEWAY_ALPN, IrohGatewayRequest, IrohGatewayResponse};
use fedimint_core::net::iroh::build_iroh_endpoint;
use fedimint_core::task::TaskGroup;
use fedimint_gateway_common::STOP_ENDPOINT;
use fedimint_logging::LOG_GATEWAY;
use iroh::endpoint::Incoming;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::json;
use tracing::info;
use url::Url;

use crate::Gateway;
use crate::error::{GatewayError, PublicGatewayError};
use crate::rpc_server::verify_bolt11_preimage_v2_get;

/// Handler for a GET request, which must contain no parameters and return
/// `serde_json::Value`
type GetHandler = Box<
    dyn Fn(
            Extension<Arc<Gateway>>,
        )
            -> Pin<Box<dyn Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send>>
        + Send
        + Sync,
>;

/// Handler for a POST request, which must contain `serde_json::Value` encoded
/// parameters and return `serde_json::Value`.
type PostHandler = Box<
    dyn Fn(
            Extension<Arc<Gateway>>,
            serde_json::Value,
        )
            -> Pin<Box<dyn Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send>>
        + Send
        + Sync,
>;

/// Creates a GET handler for the Iroh endpoint by wrapping it in a closure.
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

/// Creates a POST handler for the Iroh endpoint by wrapping it in a closure.
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

/// Helper struct for registering handlers that are called by the Iroh
/// `Endpoint`. GET handlers and POST handlers are registered separately, since
/// they contain different function signatures. If a route is authenticated, it
/// is also stored in `authenticated_routes` which is checked when the specific
/// handler is called.
pub struct Handlers {
    get_handlers: BTreeMap<String, GetHandler>,
    post_handlers: BTreeMap<String, PostHandler>,
    authenticated_routes: BTreeSet<String>,
}

impl Handlers {
    pub fn new() -> Self {
        let mut authenticated_routes = BTreeSet::new();
        authenticated_routes.insert(STOP_ENDPOINT.to_string());
        Handlers {
            get_handlers: BTreeMap::new(),
            post_handlers: BTreeMap::new(),
            authenticated_routes,
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

/// Create the Iroh `Endpoint` and spawn a thread that starts listening for
/// requests.
pub async fn start_iroh_endpoint(
    gateway: &Arc<Gateway>,
    task_group: TaskGroup,
    handlers: Arc<Handlers>,
) -> anyhow::Result<()> {
    if let Some(iroh_listen) = gateway.iroh_listen {
        info!("Building Iroh Endpoint...");
        let iroh_endpoint = build_iroh_endpoint(
            gateway.iroh_sk.clone(),
            iroh_listen,
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
            while let Some(incoming) = iroh_endpoint.accept().await {
                info!("Accepted new connection. Spawning handler...");
                tg_clone.spawn_cancellable_silent(
                    "handle endpoint accept",
                    handle_incoming_iroh_request(
                        incoming,
                        gw_clone.clone(),
                        handlers_clone.clone(),
                        tg_clone.clone(),
                    ),
                );
            }
        });

        info!(target: LOG_GATEWAY, "Successfully started iroh endpoint");
    }

    Ok(())
}

/// Handle a specific Iroh request. The request must be deserialized, matched to
/// a handler, executed, then return a response to the caller.
async fn handle_incoming_iroh_request(
    incoming: Incoming,
    gateway: Arc<Gateway>,
    handlers: Arc<Handlers>,
    task_group: TaskGroup,
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    let remote_node_id = &connection.remote_node_id()?;
    info!(%remote_node_id, "Handler received connection");
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let request = recv.read_to_end(100_000).await?;
        let request = serde_json::from_slice::<IrohGatewayRequest>(&request)?;

        let (status, body) = handle_request(
            &request,
            gateway.clone(),
            handlers.clone(),
            task_group.clone(),
        )
        .await?;

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

/// Checks if the requested route is authenticated and will reject the request
/// if the authentication is incorrect. Then it will lookup the specific handler
/// in `Handlers`, execute it, and return the function's JSON along with an HTTP
/// status code.
async fn handle_request(
    request: &IrohGatewayRequest,
    gateway: Arc<Gateway>,
    handlers: Arc<Handlers>,
    task_group: TaskGroup,
) -> anyhow::Result<(StatusCode, Json<serde_json::Value>)> {
    if handlers.is_authenticated(&request.route) && iroh_verify_password(&gateway, request).is_err()
    {
        return Ok((StatusCode::UNAUTHORIZED, Json(json!(()))));
    }

    // The STOP endpoint is handled outside of the `Handlers` struct since it has a
    // different function signature (it needs a `TaskGroup`).
    if request.route == STOP_ENDPOINT {
        let body = crate::rpc_server::stop(Extension(task_group), Extension(gateway)).await?;
        return Ok((StatusCode::OK, body));
    }

    // The handlers struct also currently does not support query parameters. The
    // LNURL-verify endpoint is the only endpoint that requires these, so we
    // handle these separately as well.
    if request.route.starts_with("/verify") {
        // Use dummy URL for easier parsing
        let url = Url::parse(&format!("http://localhost{}", request.route))?;
        // Extract segments: /verify/<payment_hash>
        let mut segments = url.path_segments().unwrap();
        let hash_str = segments.next();

        let payment_hash: sha256::Hash = hash_str.ok_or(anyhow!("No has present"))?.parse()?;

        // Parse query params (?wait etc.)
        let query_map: HashMap<String, String> = url.query_pairs().into_owned().collect();

        let body =
            verify_bolt11_preimage_v2_get(Extension(gateway), Path(payment_hash), Query(query_map))
                .await?;

        return Ok((StatusCode::OK, body));
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

/// Verifies if the supplied password in the Iroh request matches the gateway's
/// password
fn iroh_verify_password(
    gateway: &Arc<Gateway>,
    request: &IrohGatewayRequest,
) -> anyhow::Result<()> {
    if let Some(password) = request.password.as_ref()
        && bcrypt::verify(password, &gateway.bcrypt_password_hash.to_string())?
    {
        return Ok(());
    }

    Err(anyhow!("Invalid password"))
}
