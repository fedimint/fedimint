use std::net::SocketAddr;

use axum::{routing::post, Extension, Json, Router};
use fedimint_server::modules::ln::contracts::ContractId;
use tokio::sync::mpsc;
use tower_http::cors::CorsLayer;
use tracing::{debug, instrument};

use crate::{rpc::GatewayRpcSender, GatewayRequest, LnGatewayError};

#[instrument(skip_all, err)]
pub async fn pay_invoice(
    Extension(messenger): Extension<GatewayRpcSender>,
    Json(contract_id): Json<ContractId>,
) -> Result<(), LnGatewayError> {
    debug!(%contract_id, "Received request to pay invoice");
    messenger
        .send(contract_id)
        .await
        .map_err(LnGatewayError::Other)?;
    Ok(())
}

pub async fn run_webserver(
    bind_addr: SocketAddr,
    sender: mpsc::Sender<GatewayRequest>,
) -> axum::response::Result<()> {
    let messenger = GatewayRpcSender::new(sender.clone());
    let app = Router::new()
        .route("/pay_invoice", post(pay_invoice))
        .layer(Extension(messenger))
        .layer(CorsLayer::permissive());

    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
