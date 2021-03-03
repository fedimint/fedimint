use config::ServerConfig;
use mint_api::{PegInRequest, PegOutRequest, ReissuanceRequest, RequestId, SigResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tide::{Body, Request, Response};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tracing::{debug, trace};

type BsigDB = Arc<Mutex<HashMap<u64, SigResponse>>>;

#[derive(Clone, Debug)]
struct State {
    bsigs: BsigDB,
    req_sender: Sender<ClientRequest>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum ClientRequest {
    PegIn(PegInRequest),
    Reissuance(ReissuanceRequest),
    PegOut(PegOutRequest),
}

impl ClientRequest {
    pub fn dbg_type_name(&self) -> &'static str {
        match self {
            ClientRequest::PegIn(_) => "peg-in",
            ClientRequest::Reissuance(_) => "reissuance",
            ClientRequest::PegOut(_) => "peg-out",
        }
    }
}

pub async fn run_server(
    cfg: ServerConfig,
    request_sender: Sender<ClientRequest>,
    bsig_receiver: Receiver<Vec<SigResponse>>,
) {
    let bsigs = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(receive_bsigs(bsigs.clone(), bsig_receiver));

    let state = State {
        bsigs,
        req_sender: request_sender,
    };
    let mut server = tide::with_state(state);
    server.at("/issuance/pegin").put(request_issuance);
    server.at("/issuance/reissue").put(request_reissuance);
    server.at("/issuance/:req_id").get(fetch_sig);
    server
        .listen(format!("127.0.0.1:{}", cfg.get_api_port()))
        .await
        .expect("Could not start API server");
}

async fn request_issuance(mut req: Request<State>) -> tide::Result {
    trace!("Received API request {:?}", req);
    let sig_req: PegInRequest = req.body_json().await?;
    debug!("Sending peg-in request to consensus");
    req.state()
        .req_sender
        .send(ClientRequest::PegIn(sig_req))
        .await
        .expect("Could not submit sign request to consensus");

    Ok(Response::new(200))
}

async fn request_reissuance(mut req: Request<State>) -> tide::Result {
    trace!("Received API request {:?}", req);
    let reissue_req: ReissuanceRequest = req.body_json().await?;
    debug!("Sending reissuance request to consensus");
    req.state()
        .req_sender
        .send(ClientRequest::Reissuance(reissue_req))
        .await
        .expect("Could not submit reissuance request to consensus");

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

    debug!("got req for id: {}", req_id);

    if let Some(sig) = req.state().bsigs.lock().await.get(&req_id) {
        let body = Body::from_json(sig).expect("encoding error");
        debug!("response body: {:?}", body);
        Ok(body.into())
    } else {
        Ok(Response::new(404))
    }
}

async fn receive_bsigs(db: BsigDB, mut bsig_receiver: Receiver<Vec<SigResponse>>) {
    while let Some(bsigs) = bsig_receiver.recv().await {
        db.lock()
            .await
            .extend(bsigs.into_iter().map(|bsig| (bsig.id(), bsig)));
    }
}
