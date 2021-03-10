use crate::database::{BincodeSerialized, FinalizedSignatureKey};
use config::ServerConfig;
use database::{Database, DatabaseKeyPrefix, DatabaseValue};
use mint_api::{PegInRequest, PegOutRequest, ReissuanceRequest, SigResponse, TransactionId};
use serde::{Deserialize, Serialize};
use sled::Event;
use tide::{Body, Request, Response};
use tokio::sync::mpsc::Sender;
use tracing::{debug, trace};

#[derive(Clone, Debug)]
struct State {
    db: sled::Tree, // TODO: abstract
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

pub async fn run_server(cfg: ServerConfig, db: sled::Tree, request_sender: Sender<ClientRequest>) {
    let state = State {
        db,
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
    let req_id: TransactionId = match req
        .param("req_id")
        .expect("Request id not supplied")
        .parse()
    {
        Ok(id) => id,
        Err(_) => return Ok(Response::new(400)),
    };

    debug!("got req for id: {}", req_id);

    let sig_key = FinalizedSignatureKey {
        issuance_id: req_id,
    };

    let db_element = req
        .state()
        .db
        .get_value::<_, BincodeSerialized<SigResponse>>(&sig_key)
        .expect("DB error");
    if let Some(sig) = db_element {
        let body = Body::from_json(&sig.into_owned()).expect("encoding error");
        debug!("Replying instantly with signature for request {}", req_id);
        trace!("response body: {:?}", body);
        return Ok(body.into());
    }

    debug!("Waiting for signature for request {}", req_id);
    // TODO: migrate to some tokio based server and add timeout
    while let Some(event) = req.state().db.watch_prefix(sig_key.to_bytes()).await {
        match event {
            Event::Insert { key, value } => {
                assert_eq!(key, sig_key.to_bytes());
                let sig = BincodeSerialized::<SigResponse>::from_bytes(&value)
                    .expect("Database decoding error");
                let body = Body::from_json(&sig.into_owned()).expect("encoding error");
                debug!("Replying with signature for request after event {}", req_id);
                trace!("response body: {:?}", body);
                return Ok(body.into());
            }
            Event::Remove { .. } => {
                // TODO: revisit invariant when introducing epochs
                panic!("This should never happen")
            }
        }
    }

    debug!(
        "Timed out while waiting for signature for request {}",
        req_id
    );
    Ok(Response::new(404))
}
