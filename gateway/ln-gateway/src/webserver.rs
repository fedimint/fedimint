use std::net::SocketAddr;

use axum::{response::IntoResponse, routing::post, Extension, Json, Router};
use axum_macros::debug_handler;
use fedimint_server::modules::ln::contracts::ContractId;
use serde_json::json;
use tokio::sync::mpsc;
use tower_http::cors::CorsLayer;
use tracing::{debug, instrument};

use crate::{rpc::GatewayRpcSender, GatewayRequest, LnGatewayError};

/// Display gateway ecash token balance
#[debug_handler]
#[instrument(skip_all, err)]
async fn info(_: Extension<GatewayRpcSender>) -> Result<impl IntoResponse, LnGatewayError> {
    // TODO: source actual gateway info
    Ok(Json(
        json!({ "url": "http://127.0.0.1:8080", "federations": "1", "balance": "100 sats" }),
    ))
}

#[instrument(skip_all, err)]
async fn pay_invoice(
    Extension(rpc): Extension<GatewayRpcSender>,
    Json(contract_id): Json<ContractId>,
) -> Result<impl IntoResponse, LnGatewayError> {
    debug!(%contract_id, "Received request to pay invoice");
    rpc.send(contract_id).await?;
    Ok(())
}

pub async fn run_webserver(
    bind_addr: SocketAddr,
    sender: mpsc::Sender<GatewayRequest>,
) -> axum::response::Result<()> {
    let rpc = GatewayRpcSender::new(sender.clone());

    let app = Router::new()
        .route("/info", post(info))
        .route("/pay_invoice", post(pay_invoice))
        .layer(Extension(rpc))
        .layer(CorsLayer::permissive());

    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
