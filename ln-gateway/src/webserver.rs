use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::post, Extension, Json, Router};
use tokio::sync::{mpsc, oneshot, Mutex};
use tower_http::cors::CorsLayer;
use tracing::{debug, instrument};

use crate::GatewayRequestInner;
use crate::{GatewayRequest, LnGatewayError};
use fedimint_server::modules::ln::contracts::ContractId;

#[instrument(skip_all, err)]
pub async fn pay_invoice(
    extension: Extension<mpsc::Sender<GatewayRequest>>,
    Json(contract_id): Json<ContractId>,
) -> Result<(), LnGatewayError> {
    debug!(%contract_id, "Received request to pay invoice");

    let (sender, receiver) = oneshot::channel::<Result<(), LnGatewayError>>();
    let msg = GatewayRequest::PayInvoice(GatewayRequestInner {
        request: contract_id,
        sender,
    });

    let gw_sender = { extension.0.lock().await.clone() };
    gw_sender
        .send(msg)
        .await
        .expect("failed to send over channel");
    receiver.await.unwrap()?;

    Ok(())
}

pub async fn run_webserver(
    bind_addr: SocketAddr,
    sender: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
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
