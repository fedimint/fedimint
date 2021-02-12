use crate::config::ServerConfig;
use crate::mint::{Coin, RequestId, SigResponse, SignRequest};
use crate::musig;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::collections::HashMap;
use std::sync::Arc;
use tide::{Body, Request, Response};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tracing::{debug, info, trace};

type BsigDB = Arc<Mutex<HashMap<u64, SigResponse>>>;

#[derive(Clone, Debug)]
struct State {
    bsigs: BsigDB,
    req_sender: Sender<ClientRequest>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PegInRequest {
    pub blind_tokens: SignRequest,
    pub proof: (), // TODO: implement pegin
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct ReissuanceRequest {
    pub coins: Vec<Coin>,
    pub blind_tokens: SignRequest,
    pub sig: musig::Sig,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PegOutRequest {
    pub address: (), // TODO: implement pegout
    pub coins: Vec<Coin>,
    pub sig: (), // TODO: impl signing
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

impl ReissuanceRequest {
    pub fn digest(&self) -> Sha3_256 {
        let mut digest = Sha3_256::default();
        bincode::serialize_into(&mut digest, &self.coins).unwrap();
        bincode::serialize_into(&mut digest, &self.blind_tokens).unwrap();
        digest
    }
}

pub async fn run_server(
    cfg: ServerConfig,
    request_sender: Sender<ClientRequest>,
    bsig_receiver: Receiver<SigResponse>,
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
