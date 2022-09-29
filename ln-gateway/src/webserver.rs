use std::net::SocketAddr;

use anyhow::Error;
use axum::{routing::post, Extension, Json, Router};
use tokio::sync::oneshot;
use tower_http::cors::CorsLayer;
use tracing::{debug, instrument};

use crate::{rpc::GatewayRpcSender, GatewayRequest, GatewayRequestInner};
use fedimint_server::modules::ln::contracts::ContractId;

#[instrument(skip_all, err)]
pub async fn pay_invoice(
    extension: Extension<GatewayRpcSender>,
    Json(contract_id): Json<ContractId>,
) -> Result<(), Error> {
    debug!(%contract_id, "Received request to pay invoice");

    let (sender, _) = oneshot::channel::<Result<(), Error>>();

    let msg = GatewayRequest::PayInvoice(GatewayRequestInner {
        request: contract_id,
        sender,
    });

    extension.0.send(msg).await?;

    Ok(())
}

pub async fn run_webserver(
    bind_addr: SocketAddr,
    sender: GatewayRpcSender,
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
