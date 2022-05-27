use crate::config::ServerConfig;
use crate::consensus::MinimintConsensus;
use crate::transaction::Transaction;
use minimint_api::{FederationModule, TransactionId};
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
    server.at("/transaction").put(submit_transaction);
    server.at("/transaction/:txid").get(fetch_outcome);

    attach_module_endpoints(&mut server, &minimint.wallet);
    attach_module_endpoints(&mut server, &minimint.mint);
    attach_module_endpoints(&mut server, &minimint.ln);

    server
        .listen(format!("127.0.0.1:{}", cfg.get_api_port()))
        .await
        .expect("Could not start API server");
}

fn attach_module_endpoints<M>(server: &mut Server<State>, module: &M)
where
    M: FederationModule + 'static,
    for<'a> &'a M: From<&'a MinimintConsensus<rand::rngs::OsRng>>,
{
    for endpoint in module.api_endpoints() {
        // Check that params are actually defined in path spec so that there will be no errors at
        // runtime.
        for param in endpoint.params {
            assert!(
                endpoint.path_spec.contains(&format!(":{}", param)),
                "Module defined API endpoint with faulty path spec"
            );
        }

        let path = format!("/{}{}", module.api_base_name(), endpoint.path_spec);
        server
            .at(&path)
            .method(endpoint.method, move |mut req: Request<State>| async move {
                debug!(endpoint = %req.url(), "Module endpoint request");
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
                let module: &M = req.state().minimint.as_ref().into();
                (endpoint.handler)(module, params, data)
            });
    }
}

#[instrument(skip_all)]
async fn submit_transaction(mut req: Request<State>) -> tide::Result {
    trace!(?req, "Received API request");
    let transaction: Transaction = req.body_json().await?;
    let tx_id = transaction.tx_hash();
    debug!("Sending peg-in request to consensus");
    req.state()
        .minimint
        .submit_transaction(transaction)
        .expect("Could not submit sign request to consensus");

    // TODO: give feedback in case of error
    let body = Body::from_json(&tx_id).expect("encoding error");
    Ok(body.into())
}

#[instrument(skip_all)]
async fn fetch_outcome(req: Request<State>) -> tide::Result {
    let tx_hash: TransactionId = match req.param("txid").expect("Request id not supplied").parse() {
        Ok(id) => id,
        Err(_) => return Ok(Response::new(400)),
    };

    debug!(transaction = %tx_hash, "Recieved request");

    let tx_status = req
        .state()
        .minimint
        .transaction_status(tx_hash)
        .ok_or_else(|| tide::Error::from_str(404, "Not found"))?;

    debug!(transaction = %tx_hash, "Sending outcome");
    let body = Body::from_json(&tx_status).expect("encoding error");
    Ok(body.into())
}
