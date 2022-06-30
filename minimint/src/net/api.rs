use crate::config::ServerConfig;
use crate::consensus::MinimintConsensus;
use crate::transaction::Transaction;
use minimint_api::{
    module::{http, ApiEndpoint},
    FederationModule, TransactionId,
};
use std::fmt::Formatter;
use std::sync::Arc;
use tide::{Body, Request, Response, Server};
use tracing::{debug, instrument, trace};

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
    let mut server = tide::with_state(state);

    attach_endpoints(&mut server, server_endpoints(), None);
    attach_endpoints(
        &mut server,
        minimint.wallet.api_endpoints(),
        Some(minimint.wallet.api_base_name()),
    );
    attach_endpoints(
        &mut server,
        minimint.mint.api_endpoints(),
        Some(minimint.mint.api_base_name()),
    );
    attach_endpoints(
        &mut server,
        minimint.ln.api_endpoints(),
        Some(minimint.ln.api_base_name()),
    );

    server
        .listen(&cfg.api_bind_addr)
        .await
        .expect("Could not start API server");
}

fn attach_endpoints<M>(
    server: &mut Server<State>,
    endpoints: &'static [ApiEndpoint<M>],
    base_name: Option<&str>,
) where
    MinimintConsensus<rand::rngs::OsRng>: AsRef<M>,
{
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
        server
            .at(&path)
            .method(endpoint.method, move |mut req: Request<State>| async move {
                debug!(endpoint = %req.url(), "Endpoint request");
                let data: serde_json::Value = req.body_json().await.unwrap_or_default();
                let params = endpoint
                    .params
                    .iter()
                    .map(|param| {
                        let value = req
                            .param(param)
                            .expect("We previously checked the param exists in the path spec");
                        (*param, value)
                    })
                    .collect();
                let module: &M = req.state().minimint.as_ref().as_ref();
                (endpoint.handler)(module, params, data)
            });
    }
}

fn server_endpoints() -> &'static [ApiEndpoint<MinimintConsensus<rand::rngs::OsRng>>] {
    &[
        ApiEndpoint {
            path_spec: "/transaction",
            params: &[],
            method: http::Method::Put,
            handler: |minimint, _params, transaction| {
                let transaction: Transaction = match serde_json::from_value(transaction) {
                    Ok(t) => t,
                    Err(_) => return Ok(http::Response::new(400)),
                };
                let tx_id = transaction.tx_hash();

                minimint
                    .submit_transaction(transaction)
                    .expect("Could not submit sign request to consensus");

                // TODO: give feedback in case of error
                let body = Body::from_json(&tx_id).expect("encoding error");
                Ok(body.into())
            },
        },
        ApiEndpoint {
            path_spec: "/transaction/:txid",
            params: &["txid"],
            method: http::Method::Get,
            handler: |minimint, params, _body| {
                let tx_hash: TransactionId =
                    match params.get("txid").expect("Request id not supplied").parse() {
                        Ok(id) => id,
                        Err(_) => return Ok(http::Response::new(400)),
                    };

                debug!(transaction = %tx_hash, "Recieved request");

                let tx_status = match minimint.transaction_status(tx_hash) {
                    Some(t) => t,
                    None => return Ok(http::Response::new(404)),
                };

                debug!(transaction = %tx_hash, "Sending outcome");
                let body = Body::from_json(&tx_status).expect("encoding error");
                Ok(body.into())
            },
        },
    ]
}
