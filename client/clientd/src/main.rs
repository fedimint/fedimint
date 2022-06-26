use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router, Server};
use bitcoin_hashes::hex::ToHex;
use clap::Parser;
use clientd::payload::{LnPayPayload, PeginPayload, PegoutPayload};
use clientd::responses::{
    EventsResponse, InfoResponse, PegInOutResponse, PeginAddressResponse, PendingResponse,
    ReissueResponse, RpcResult, SpendResponse,
};
use clientd::{Event, EventLog};
use minimint_api::Amount;
use minimint_core::config::load_from_file;
use minimint_core::modules::mint::tiered::coins::Coins;
use mint_client::api::ApiError::HttpError;
use mint_client::clients::user::ClientError;
use mint_client::ln::gateway::LightningGateway;
use mint_client::ln::LnClientError::ApiError;
use mint_client::mint::SpendableCoin;
use mint_client::utils::serialize_coins;
use mint_client::{ClientAndGatewayConfig, UserClient};
use rand::rngs::OsRng;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tower::ServiceBuilder;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Config {
    workdir: PathBuf,
}
struct State {
    client: Arc<UserClient>,
    gateway: Arc<LightningGateway>,
    event_log: Arc<EventLog>,
    fetch_tx: Sender<()>,
    rng: OsRng,
}
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let opts: Config = Config::parse();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: ClientAndGatewayConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();

    let client = Arc::new(UserClient::new(
        cfg.client,
        Box::new(db),
        Default::default(),
    ));
    let gateway = Arc::new(cfg.gateway.clone());
    let (tx, mut rx) = mpsc::channel(1024);
    let event_log = Arc::new(EventLog::new(1024));
    let rng = OsRng::new().unwrap();

    let shared_state = Arc::new(State {
        client: Arc::clone(&client),
        gateway: Arc::clone(&gateway),
        event_log: Arc::clone(&event_log),
        fetch_tx: tx,
        rng,
    });

    let app = Router::new()
        .route("/getInfo", post(info))
        .route("/getPending", post(pending))
        .route("/getPeginAdress", post(pegin_address))
        .route("/getEvents", post(events))
        .route("/pegin", post(pegin))
        .route("/pegout", post(pegout))
        .route("/spend", post(spend))
        .route("/reissue", post(reissue))
        .route("/reissueValidate", post(reissue_validate))
        .route("/lnpay", post(lnpay))
        .layer(
            ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(DefaultMakeSpan::new().include_headers(true))
                        .on_request(DefaultOnRequest::new().level(Level::INFO))
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .layer(Extension(shared_state)),
        );

    let fetch_client = Arc::clone(&client);
    let fetch_event_log = Arc::clone(&event_log);
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            fetch(Arc::clone(&fetch_client), Arc::clone(&fetch_event_log)).await;
        }
    });

    Server::bind(&"127.0.0.1:8081".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn info(Extension(state): Extension<Arc<State>>) -> impl IntoResponse {
    let client = &state.client;
    Json(RpcResult::Success(json!(InfoResponse::new(
        client.coins(),
        client.fetch_active_issuances(),
    ))))
}

async fn pending(Extension(state): Extension<Arc<State>>) -> impl IntoResponse {
    let client = &state.client;
    Json(RpcResult::Success(json!(PendingResponse::new(
        client.fetch_active_issuances()
    ))))
}

async fn pegin_address(Extension(state): Extension<Arc<State>>) -> impl IntoResponse {
    let client = &state.client;
    let mut rng = state.rng.clone();
    Json(RpcResult::Success(json!(PeginAddressResponse::new(
        client.get_new_pegin_address(&mut rng),
    ))))
}

async fn events(Extension(state): Extension<Arc<State>>, payload: Json<u64>) -> impl IntoResponse {
    let timestamp = payload.0;
    let event_log = &state.event_log;
    let queried_events = event_log.get(timestamp).await;
    Json(RpcResult::Success(json!(EventsResponse::new(
        queried_events
    ))))
}

async fn pegin(
    Extension(state): Extension<Arc<State>>,
    payload: Json<PeginPayload>,
) -> impl IntoResponse {
    let client = &state.client;
    let event_log = &state.event_log;
    let mut rng = state.rng.clone();
    let txout_proof = payload.0.txout_proof;
    let transaction = payload.0.transaction;
    let txid = match client.peg_in(txout_proof, transaction, &mut rng).await {
        Ok(txid) => {
            let txid_hex = txid.to_hex();
            info!("Started peg-in {}, result will be fetched", txid_hex);
            event_log
                .add(format!(
                    "Started peg-in {}, result will be fetched",
                    txid_hex
                ))
                .await;
            txid
        }
        Err(e) => {
            let err_res = Event::new(format!("{:?}", e));
            event_log.add_event(err_res.clone()).await;
            return Json(RpcResult::Failure(json!(err_res)));
        }
    };
    Json(RpcResult::Success(json!(PegInOutResponse::new(txid))))
}

async fn pegout(
    Extension(state): Extension<Arc<State>>,
    payload: Json<PegoutPayload>,
) -> impl IntoResponse {
    let client = &state.client;
    let event_log = &state.event_log;
    let mut rng = state.rng.clone();
    let address = payload.0.address;
    let amt = payload.0.amount;
    let txid = match client.peg_out(amt, address, &mut rng).await {
        Ok(txid) => {
            let txid_hex = txid.to_hex();
            info!("Pegged out {} with txid: {}", amt, txid_hex);
            event_log
                .add(format!("Pegged out {} with txid: {}", amt, txid_hex))
                .await;
            txid
        }
        Err(e) => {
            let err_res = Event::new(format!("{:?}", e));
            event_log.add_event(err_res.clone()).await;
            return Json(RpcResult::Failure(json!(err_res)));
        }
    };
    Json(RpcResult::Success(json!(PegInOutResponse::new(txid))))
}

//TODO: wait for https://github.com/fedimint/minimint/issues/80 and implement solution for this handler
async fn spend(
    Extension(state): Extension<Arc<State>>,
    payload: Json<Amount>,
) -> impl IntoResponse {
    let client = &state.client;
    let event_log = &state.event_log;
    let amount = payload.0;

    let spending_coins = match client.select_and_spend_coins(amount) {
        Ok(c) => {
            event_log
                .add(format!(
                    "successfully spend coins: msat: {}, ecash: {}",
                    amount.milli_sat,
                    serialize_coins(&c)
                ))
                .await;
            c
        }
        Err(e) => {
            let err_res = Event::new(format!("{:?}", e));
            event_log.add_event(err_res.clone()).await;
            return Json(RpcResult::Failure(json!(err_res)));
        }
    };
    Json(RpcResult::Success(json!(SpendResponse::new(
        spending_coins
    ))))
}

async fn reissue(Extension(state): Extension<Arc<State>>, payload: Json<Coins<SpendableCoin>>) {
    let state = Arc::clone(&state);
    let coins = payload.0;
    tokio::spawn(async move {
        let client = &state.client;
        let event_log = &state.event_log;
        let fetch_tx = state.fetch_tx.clone();
        let mut rng = state.rng.clone();
        match client.reissue(coins, &mut rng).await {
            Ok(o) => {
                event_log
                    .add(format!("Successful reissue, outpoint: {:?}", o))
                    .await;
                if let Err(e) = fetch_tx.send(()).await {
                    event_log
                        .add(format!("Critical error, restart the deamon: {}", e))
                        .await;
                }
            }
            Err(e) => {
                event_log.add(format!("Error while reissue: {:?}", e)).await;
            }
        }
    });
}

async fn reissue_validate(
    Extension(state): Extension<Arc<State>>,
    payload: Json<Coins<SpendableCoin>>,
) -> impl IntoResponse {
    let client = &state.client;
    let event_log = &state.event_log;
    let coins = payload.0;
    let fetch_tx = state.fetch_tx.clone();
    let mut rng = state.rng.clone();
    let outpoint = match client.reissue(coins, &mut rng).await {
        Ok(outpoint) => {
            event_log
                .add(format!("Successful reissue, outpoint: {:?}", outpoint))
                .await;
            if let Err(e) = fetch_tx.send(()).await {
                event_log
                    .add(format!("Critical error, restart the deamon: {}", e))
                    .await;
            }
            outpoint
        }
        Err(e) => {
            let event = Event::new(format!("Error while reissue: {:?}", e));
            event_log.add_event(event.clone()).await;
            return Json(RpcResult::Failure(json!(event)));
        }
    };
    //unwrap ok since this is polling=true
    let status = client.fetch_tx_outcome(outpoint.txid, true).await.unwrap();
    Json(RpcResult::Success(json!(ReissueResponse::new(
        outpoint, status
    ))))
}

//TODO: wait for https://github.com/fedimint/minimint/issues/80 and implement solution for this handler
async fn lnpay(
    Extension(state): Extension<Arc<State>>,
    payload: Json<LnPayPayload>,
) -> impl IntoResponse {
    let client = Arc::clone(&state.client);
    let gateway = Arc::clone(&state.gateway);
    let event_log = &state.event_log;
    let rng = state.rng.clone();
    let invoice = payload.0.bolt11;

    return match pay_invoice(invoice, client, gateway, rng).await {
        Ok(_) => {
            let event = Event::new("Success".to_string());
            event_log.add_event(event.clone()).await;
            Json(RpcResult::Success(json!(event)))
        }
        Err(e) => {
            let event = Event::new(format!("Error paying invoice: {:?}", e));
            event_log.add_event(event.clone()).await;
            Json(RpcResult::Failure(json!(event)))
        }
    };
}

async fn fetch(client: Arc<UserClient>, event_log: Arc<EventLog>) {
    match client.fetch_all_coins().await {
        Ok(txids) => {
            //if there are active issuances accumulated they'll all be fetched at once leaving active issuances empty
            //this is not 'deterministic' though so it can happen that client.fetch_all_coins() will return ok but with an empty vec
            if !txids.is_empty() {
                event_log
                    .add(format!("successfully fetched: {:?}", txids))
                    .await;
            }
        }
        Err(e) => {
            event_log
                .add(format!("Error while fetching: {:?}", e))
                .await;
        }
    };
}

async fn pay_invoice(
    bolt11: lightning_invoice::Invoice,
    client: Arc<UserClient>,
    gateway: Arc<LightningGateway>,
    mut rng: OsRng,
) -> Result<(), ClientError> {
    let http = reqwest::Client::new();

    let (contract_id, outpoint) = client
        .fund_outgoing_ln_contract(&*gateway, bolt11, &mut rng)
        .await
        .expect("Not enough coins");

    client
        .await_outgoing_contract_acceptance(outpoint)
        .await
        .expect("Contract wasn't accepted in time");

    info!(
        %contract_id,
        "Funded outgoing contract, notifying gateway",
    );

    let response = http
        .post(&format!("{}/pay_invoice", &*gateway.api))
        .json(&contract_id)
        .timeout(Duration::from_secs(15))
        .send()
        .await;

    match response {
        Ok(_) => Ok(()),
        Err(e) => Err(ClientError::LnClientError(ApiError(HttpError(e)))),
    }
}
