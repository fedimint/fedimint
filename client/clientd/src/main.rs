mod utils;

use crate::utils::payload::{LnPayPayload, PeginPayload};
use crate::utils::responses::{
    EventsResponse, InfoResponse, PegInOutResponse, PeginAddressResponse, PendingResponse,
    SpendResponse,
};
use crate::utils::{Event, EventLog, JsonDecodeTransaction};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router, Server};
use bitcoin_hashes::hex::ToHex;
use clap::Parser;
use minimint_api::Amount;
use minimint_core::config::load_from_file;
use minimint_core::modules::mint::tiered::coins::Coins;
use mint_client::api::ApiError::HttpError;
use mint_client::clients::user::ClientError;
use mint_client::ln::gateway::LightningGateway;
use mint_client::ln::LnClientError::ApiError;
use mint_client::mint::SpendableCoin;
use mint_client::{ClientAndGatewayConfig, UserClient};
use rand::rngs::OsRng;
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
        .route("/spend", post(spend))
        .route("/reissue", post(reissue))
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
    Json(InfoResponse::new(
        client.coins(),
        client.fetch_active_issuances(),
    ))
}

async fn pending(Extension(state): Extension<Arc<State>>) -> impl IntoResponse {
    let client = &state.client;
    Json(PendingResponse::new(client.fetch_active_issuances()))
}

async fn pegin_address(Extension(state): Extension<Arc<State>>) -> impl IntoResponse {
    let client = &state.client;
    let mut rng = state.rng.clone();
    Json(PeginAddressResponse::new(
        client.get_new_pegin_address(&mut rng),
    ))
}

async fn events(Extension(state): Extension<Arc<State>>, payload: Json<u64>) -> impl IntoResponse {
    let timestamp = payload.0;
    let event_log = &state.event_log;
    let queried_events = event_log.get(timestamp).await;
    Json(EventsResponse::new(queried_events))
}

async fn pegin(
    Extension(state): Extension<Arc<State>>,
    payload: JsonDecodeTransaction,
) -> impl IntoResponse {
    let client = &state.client;
    let mut rng = state.rng.clone();
    let txout_proof = payload.0.txout_proof;
    let transaction = payload.0.transaction;
    let txid = client
        .peg_in(txout_proof, transaction, &mut rng)
        .await
        .unwrap(); //TODO: handle unwrap()
    info!("Started peg-in {}, result will be fetched", txid.to_hex());
    Json(PegInOutResponse::new(txid))
}

//TODO: wait for https://github.com/fedimint/minimint/issues/80 and implement solution for this handler
async fn spend(
    Extension(state): Extension<Arc<State>>,
    payload: Json<Amount>,
) -> impl IntoResponse {
    let client = &state.client;
    let amount = payload.0;

    let spending_coins = client.select_and_spend_coins(amount).unwrap(); //TODO: handle unwrap()
    Json(SpendResponse::new(spending_coins))
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

//TODO: wait for https://github.com/fedimint/minimint/issues/80 and implement solution for this handler
async fn lnpay(
    Extension(state): Extension<Arc<State>>,
    payload: Json<LnPayPayload>,
) -> impl IntoResponse {
    let client = Arc::clone(&state.client);
    let gateway = Arc::clone(&state.gateway);
    let rng = state.rng.clone();
    let invoice = payload.0.bolt11;

    match pay_invoice(invoice, client, gateway, rng).await {
        Ok(_) => Json(Event::new("Success".to_string())),
        Err(e) => Json(Event::new(format!("Error paying invoice: {:?}", e))),
    }
}

async fn fetch(client: Arc<UserClient>, event_log: Arc<EventLog>) {
    match client.fetch_all_coins().await {
        Ok(txids) => {
            //if there are active issuances accumulated they'll all be fetched at once leaving active issuances empty
            //this is not 'deterministic' though so it can happen that client.fetch_all_coins() will return ok but with an empty vec
            if !txids.is_empty() {
                event_log
                    .add(format!("successfully fetched: {:?}", txids))
                    .await
            }
        }
        Err(e) => {
            event_log
                .add(format!("Error while fetching: {:?}", e))
                .await
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
