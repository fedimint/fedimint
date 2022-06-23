mod utils;

use crate::utils::payload::PeginPayload;
use crate::utils::responses::{
    InfoResponse, PegInOutResponse, PeginAddressResponse, PendingResponse, SpendResponse,
};
use crate::utils::JsonDecodeTransaction;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router, Server};
use bitcoin_hashes::hex::ToHex;
use clap::Parser;
use minimint_api::Amount;
use minimint_core::config::load_from_file;
use minimint_core::modules::mint::tiered::coins::Coins;
use mint_client::mint::SpendableCoin;
use mint_client::{ClientAndGatewayConfig, UserClient};
use rand::rngs::OsRng;
use std::path::PathBuf;
use std::sync::Arc;
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
    let (tx, mut rx) = mpsc::channel(1024);
    let rng = OsRng::new().unwrap();

    let shared_state = Arc::new(State {
        client: Arc::clone(&client),
        fetch_tx: tx,
        rng,
    });

    let app = Router::new()
        .route("/getInfo", post(info))
        .route("/getPending", post(pending))
        .route("/getPeginAdress", post(pegin_address))
        .route("/pegin", post(pegin))
        .route("/spend", post(spend))
        .route("/reissue", post(reissue))
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
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            fetch(Arc::clone(&fetch_client)).await;
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
        let fetch_tx = state.fetch_tx.clone();
        let mut rng = state.rng.clone();
        //TODO: log what happens here and handle unwraps()
        client.reissue(coins, &mut rng).await.unwrap();
        fetch_tx.send(()).await.unwrap();
    });
}

async fn fetch(client: Arc<UserClient>) {
    //TODO: log txid or error (handle unwrap)
    client.fetch_all_coins().await.unwrap();
}
