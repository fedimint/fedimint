use config::ServerConfig;
use database::RawDatabase;
use mint_api::transaction::Transaction;
use mint_api::TransactionId;
use std::fmt::Formatter;
use std::sync::Arc;
use tide::{Body, Request, Response};
use tokio::sync::mpsc::Sender;
use tracing::{debug, trace};

#[derive(Clone)]
struct State {
    db: Arc<dyn RawDatabase>,
    req_sender: Sender<Transaction>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("State { ... }")
    }
}

pub async fn run_server(
    cfg: ServerConfig,
    db: Arc<dyn RawDatabase>,
    request_sender: Sender<Transaction>,
) {
    let state = State {
        db,
        req_sender: request_sender,
    };
    let mut server = tide::with_state(state);
    server.at("/transaction").put(submit_transaction);
    server.at("/transaction/:txid").get(fetch_outcome);
    server
        .listen(format!("127.0.0.1:{}", cfg.get_api_port()))
        .await
        .expect("Could not start API server");
}

async fn submit_transaction(mut req: Request<State>) -> tide::Result {
    trace!("Received API request {:?}", req);
    let transaction: Transaction = req.body_json().await?;
    debug!("Sending peg-in request to consensus");
    req.state()
        .req_sender
        .send(transaction)
        .await
        .expect("Could not submit sign request to consensus");

    // TODO: give feedback
    Ok(Response::new(200))
}

async fn fetch_outcome(req: Request<State>) -> tide::Result {
    let tx_hash: TransactionId = match req.param("txid").expect("Request id not supplied").parse() {
        Ok(id) => id,
        Err(_) => return Ok(Response::new(400)),
    };

    debug!("Got req for transaction state {}", tx_hash);

    let tx_status = crate::database::load_tx_outcome(req.state().db.as_ref(), tx_hash)
        .expect("DB error")
        .ok_or(tide::Error::from_str(404, "Not found"))?;

    debug!("Sending outcome of transaction {}", tx_hash);
    let body = Body::from_json(&tx_status).expect("encoding error");
    Ok(body.into())
}
