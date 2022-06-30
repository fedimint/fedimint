use crate::config::ServerConfig;
use crate::consensus::MinimintConsensus;
use crate::transaction::Transaction;
use axum::{
    body::{Body, HttpBody},
    http::{Request, StatusCode},
    response::IntoResponse,
};
use minimint_api::{
    module::{http, ApiEndpoint},
    FederationModule, TransactionId,
};
use std::sync::Arc;
use std::{collections::HashMap, fmt::Formatter};
use tracing::debug;

#[derive(Clone)]
struct State {
    minimint: Arc<MinimintConsensus<rand::rngs::OsRng>>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("State { ... }")
    }
}

pub async fn run_server(cfg: ServerConfig, minimint: Arc<MinimintConsensus<rand::rngs::OsRng>>) {
    let state = State {
        minimint: minimint.clone(),
    };
    let mut router = axum::Router::new();

    router = attach_endpoints(router, server_endpoints(), None);
    router = attach_endpoints(
        router,
        minimint.wallet.api_endpoints(),
        Some(minimint.wallet.api_base_name()),
    );
    router = attach_endpoints(
        router,
        minimint.mint.api_endpoints(),
        Some(minimint.mint.api_base_name()),
    );
    router = attach_endpoints(
        router,
        minimint.ln.api_endpoints(),
        Some(minimint.ln.api_base_name()),
    );

    let router = router.layer(axum::Extension(state));

    axum::Server::bind(&cfg.api_bind_addr.parse().unwrap())
        .serve(router.into_make_service())
        .await
        .expect("Could not start API server");
}

fn attach_endpoints<M>(
    mut router: axum::Router,
    endpoints: &'static [ApiEndpoint<M>],
    base_name: Option<&str>,
) -> axum::Router
where
    MinimintConsensus<rand::rngs::OsRng>: AsRef<M>,
{
    use axum::extract::{Extension, Json, Path};
    use axum::routing::MethodFilter;

    for endpoint in endpoints {
        for param in endpoint.params {
            assert!(
                endpoint.path_spec.contains(&format!(":{}", param)),
                "Module defined API endpoint with faulty path spec"
            );
        }
        let path = if let Some(base_name) = base_name {
            format!("/{}{}", base_name, endpoint.path_spec)
        } else {
            endpoint.path_spec.to_string()
        };
        let method_filter = match endpoint.method {
            http::Method::GET => MethodFilter::GET,
            http::Method::POST => MethodFilter::POST,
            http::Method::PUT => MethodFilter::PUT,
            http::Method::HEAD => MethodFilter::HEAD,
            http::Method::PATCH => MethodFilter::PATCH,
            http::Method::DELETE => MethodFilter::DELETE,
            http::Method::TRACE => MethodFilter::TRACE,
            http::Method::OPTIONS => MethodFilter::OPTIONS,
            _ => unimplemented!("unknown method"),
        };

        router = router.route(
            &path,
            axum::routing::on(
                method_filter,
                move |Extension(State { minimint }),
                      Path(params): Path<HashMap<String, String>>,
                      body: Option<Json<serde_json::Value>>| async move {
                    let module: &M = (*minimint).as_ref();

                    let borrowed_params = params
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();

                    let response =
                        (endpoint.handler)(module, borrowed_params, body.unwrap_or_default().0);
                    match response {
                        Ok(r) => r.0.map(|body| body.boxed_unsync()).into_response(),
                        Err(e) => {
                            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                        }
                    }
                },
            ),
        );
    }
    router
}

fn server_endpoints() -> &'static [ApiEndpoint<MinimintConsensus<rand::rngs::OsRng>>] {
    &[
        ApiEndpoint {
            path_spec: "/transaction",
            params: &[],
            method: http::Method::PUT,
            handler: |minimint, _params, transaction| {
                let transaction: Transaction = match serde_json::from_value(transaction) {
                    Ok(t) => t,
                    Err(_) => return Ok(http::StatusCode::BAD_REQUEST.into()),
                };
                let tx_id = transaction.tx_hash();

                minimint
                    .submit_transaction(transaction)
                    .expect("Could not submit sign request to consensus");

                // TODO: give feedback in case of error
                Ok(http::Response::json(&tx_id).expect("encoding error"))
            },
        },
        ApiEndpoint {
            path_spec: "/transaction/:txid",
            params: &["txid"],
            method: http::Method::GET,
            handler: |minimint, params, _body| {
                let tx_hash: TransactionId =
                    match params.get("txid").expect("Request id not supplied").parse() {
                        Ok(id) => id,
                        Err(_) => return Ok(http::StatusCode::BAD_REQUEST.into()),
                    };

                debug!(transaction = %tx_hash, "Recieved request");

                let tx_status = match minimint.transaction_status(tx_hash) {
                    Some(t) => t,
                    None => return Ok(http::StatusCode::NOT_FOUND.into()),
                };

                debug!(transaction = %tx_hash, "Sending outcome");
                Ok(http::Response::json(&tx_status).expect("encoding error"))
            },
        },
    ]
}
