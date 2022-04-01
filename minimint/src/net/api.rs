use crate::config::ServerConfig;
use crate::consensus::FediMintConsensus;
use crate::transaction::Transaction;
use minimint_api::{FederationModule, TransactionId};
use minimint_ln::contracts::ContractId;
use std::fmt::Formatter;
use std::sync::Arc;
use tide::{Body, Request, Response, Server};
use tracing::{debug, trace};

#[derive(Clone)]
struct State {
    fedimint: Arc<FediMintConsensus<rand::rngs::OsRng>>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("State { ... }")
    }
}

pub async fn run_server(cfg: ServerConfig, fedimint: Arc<FediMintConsensus<rand::rngs::OsRng>>) {
    let state = State {
        fedimint: fedimint.clone(),
    };
    let mut server = tide::with_state(state);
    server.at("/transaction").put(submit_transaction);
    server.at("/transaction/:txid").get(fetch_outcome);
    server.at("/offers").get(list_offers);
    server.at("/account/:contract_id").get(get_contract_account);

    attach_module_endpoints(&mut server, &fedimint.wallet);
    attach_module_endpoints(&mut server, &fedimint.mint);
    attach_module_endpoints(&mut server, &fedimint.ln);

    server
        .listen(format!("127.0.0.1:{}", cfg.get_api_port()))
        .await
        .expect("Could not start API server");
}

fn attach_module_endpoints<M>(server: &mut Server<State>, module: &M)
where
    M: FederationModule + 'static,
    for<'a> &'a M: From<&'a FediMintConsensus<rand::rngs::OsRng>>,
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
                debug!("Received request for module API endpoint {}", req.url());
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
                let module: &M = req.state().fedimint.as_ref().into();
                (endpoint.handler)(module, params, data)
            });
    }
}

async fn submit_transaction(mut req: Request<State>) -> tide::Result {
    trace!("Received API request {:?}", req);
    let transaction: Transaction = req.body_json().await?;
    let tx_id = transaction.tx_hash();
    debug!("Sending peg-in request to consensus");
    req.state()
        .fedimint
        .submit_transaction(transaction)
        .expect("Could not submit sign request to consensus");

    // TODO: give feedback in case of error
    let body = Body::from_json(&tx_id).expect("encoding error");
    Ok(body.into())
}

async fn fetch_outcome(req: Request<State>) -> tide::Result {
    let tx_hash: TransactionId = match req.param("txid").expect("Request id not supplied").parse() {
        Ok(id) => id,
        Err(_) => return Ok(Response::new(400)),
    };

    debug!("Got req for transaction state {}", tx_hash);

    let tx_status = req
        .state()
        .fedimint
        .transaction_status(tx_hash)
        .ok_or_else(|| tide::Error::from_str(404, "Not found"))?;

    debug!("Sending outcome of transaction {}", tx_hash);
    let body = Body::from_json(&tx_status).expect("encoding error");
    Ok(body.into())
}

async fn list_offers(req: Request<State>) -> tide::Result {
    let offers = req.state().fedimint.ln.get_offers();

    let body = Body::from_json(&offers).expect("encoding error");
    Ok(body.into())
}

async fn get_contract_account(req: Request<State>) -> tide::Result {
    let contract_id: ContractId = match req
        .param("contract_id")
        .expect("Contract id not supplied")
        .parse()
    {
        Ok(id) => id,
        Err(_) => return Ok(Response::new(400)),
    };

    let contract_account = req
        .state()
        .fedimint
        .ln
        .get_contract_account(contract_id)
        .ok_or_else(|| tide::Error::from_str(404, "Not found"))?;

    debug!("Sending contract account info for {}", contract_id);
    let body = Body::from_json(&contract_account).expect("encoding error");
    Ok(body.into())
}
