use axum::{routing::post, Extension, Json, Router};

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tower_http::cors::CorsLayer;
use tracing::{debug, instrument};

use crate::GatewayRequestInner;
use crate::{GatewayRequest, LnGatewayError};
use minimint::modules::ln::contracts::ContractId;

#[instrument(skip_all, err)]
pub async fn pay_invoice(
    Extension(gw_sender): Extension<mpsc::Sender<GatewayRequest>>,
    Json(contract_id): Json<ContractId>,
) -> Result<(), LnGatewayError> {
    debug!(%contract_id, "Received request to pay invoice");

    let (sender, receiver) = oneshot::channel::<Result<(), LnGatewayError>>();

    let msg = GatewayRequest::PayInvoice(GatewayRequestInner {
        request: contract_id,
        sender,
    });
    gw_sender
        .send(msg)
        .await
        .expect("failed to send over channel");
    receiver.await.unwrap()?;

    Ok(())
}

pub async fn run_webserver(sender: mpsc::Sender<GatewayRequest>) -> axum::response::Result<()> {
    let app = Router::new()
        .route("/pay_invoice", post(pay_invoice))
        .layer(Extension(sender))
        .layer(CorsLayer::permissive());

    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
