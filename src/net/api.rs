use crate::config::ServerConfig;
use crate::mint::{RequestId, SigResponse, SignRequest};
use std::collections::HashMap;
use std::sync::Arc;
use tide::{Body, Request, Response};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tracing::{debug, info};

type BsigDB = Arc<Mutex<HashMap<u64, SigResponse>>>;

#[derive(Clone)]
struct State {
    bsigs: BsigDB,
    req_sender: Sender<SignRequest>,
}

pub async fn run_server(
    cfg: ServerConfig,
    request_sender: Sender<SignRequest>,
    bsig_receiver: Receiver<SigResponse>,
) {
    let bsigs = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(receive_bsigs(bsigs.clone(), bsig_receiver));

    let state = State {
        bsigs,
        req_sender: request_sender,
    };
    let mut server = tide::with_state(state);
    server.at("/issuance").put(request_issuance);
    server.at("/issuance/:req_id").get(fetch_sig);
    server
        .listen(format!("127.0.0.1:{}", cfg.get_api_port()))
        .await
        .expect("Could not start API server");
}

async fn request_issuance(mut req: Request<State>) -> tide::Result {
    let sig_req: SignRequest = req.body_json().await?;
    req.state()
        .req_sender
        .send(sig_req)
        .await
        .expect("Could not submit sign request to consensus");

    Ok(Response::new(200))
}

async fn fetch_sig(req: Request<State>) -> tide::Result {
    let req_id: u64 = match req
        .param("req_id")
        .expect("Request id not supplied")
        .parse()
    {
        Ok(id) => id,
        Err(_) => return Ok(Response::new(400)),
    };

    info!("got req for id: {}", req_id);

    if let Some(sig) = req.state().bsigs.lock().await.get(&req_id) {
        let body = Body::from_json(sig).expect("encoding error");
        debug!("response body: {:?}", body);
        Ok(body.into())
    } else {
        Ok(Response::new(404))
    }
}

async fn receive_bsigs(db: BsigDB, mut bsig_receiver: Receiver<SigResponse>) {
    while let Some(bsig) = bsig_receiver.recv().await {
        db.lock().await.insert(bsig.id(), bsig);
    }
}
