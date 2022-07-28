use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router, Server};
use clap::Parser;
use clientd::{InfoResponse, PendingResponse, RpcResult};
use minimint_core::config::load_from_file;
use mint_client::{Client, UserClientConfig};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Config {
    workdir: PathBuf,
}
struct State {
    client: Client<UserClientConfig>,
}
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let opts = Config::parse();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: UserClientConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();

    let client = Client::new(cfg.clone(), Box::new(db), Default::default()).await;

    let shared_state = Arc::new(State { client });
    let app = Router::new()
        .route("/get_info", post(info))
        .route("/get_pending", post(pending))
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

/// Handler for "get_info", returns all the clients holdings and pending transactions
async fn info(Extension(state): Extension<Arc<State>>) -> impl IntoResponse {
    let client = &state.client;
    Json(RpcResult::Success(json!(InfoResponse::new(
        client.coins(),
        client.list_active_issuances(),
    ))))
}

/// Handler for "get_pending", returns the clients pending transactions
async fn pending(Extension(state): Extension<Arc<State>>) -> impl IntoResponse {
    let client = &state.client;
    Json(RpcResult::Success(json!(PendingResponse::new(
        client.list_active_issuances()
    ))))
}
