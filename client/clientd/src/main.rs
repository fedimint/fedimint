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
use mint_client::{ClientAndGatewayConfig, UserClient};
use rand::rngs::OsRng;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Config {
    workdir: PathBuf,
}
struct State {
    client: UserClient,
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

    let client = UserClient::new(cfg.client, Box::new(db), Default::default());
    let rng = OsRng::new().unwrap();

    let shared_state = Arc::new(State { client, rng });

    let app = Router::new()
        .route("/getInfo", post(info))
        .route("/getPending", post(pending))
        .route("/getPeginAdress", post(pegin_address))
        .route("/pegin", post(pegin))
        .route("/spend", post(spend))
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
