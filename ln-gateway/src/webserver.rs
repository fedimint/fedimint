use std::net::SocketAddr;

use axum::{routing::post, Extension, Json, Router};
use fedimint_server::modules::ln::contracts::ContractId;
use tower_http::cors::CorsLayer;
use tracing::{debug, instrument};

use crate::{GatewayMessageChannel, LnGatewayError};

#[instrument(skip_all, err)]
pub async fn pay_invoice(
    Extension(sender): Extension<GatewayMessageChannel>,
    Json(contract_id): Json<ContractId>,
) -> Result<(), LnGatewayError> {
    debug!(%contract_id, "Received request to pay invoice");
    sender
        .send(contract_id)
        .await
        .map_err(LnGatewayError::Other)?;
    Ok(())
}

pub async fn run_webserver(
    sender: GatewayMessageChannel,
    bind_addr: SocketAddr,
) -> axum::response::Result<()> {
    let app = Router::new()
        .route("/pay_invoice", post(pay_invoice))
        .layer(Extension(sender))
        .layer(CorsLayer::permissive());

    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
