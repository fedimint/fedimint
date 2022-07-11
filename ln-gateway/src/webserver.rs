use std::sync::Arc;

use tide::Response;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

use crate::{GatewayRequest, LnGatewayError};
use minimint::modules::ln::contracts::ContractId;

#[instrument(skip_all, err)]
pub async fn pay_invoice(
    mut req: tide::Request<Arc<Mutex<mpsc::Sender<GatewayRequest>>>>,
) -> tide::Result {
    let contract_id: ContractId = req.body_json().await?;
    debug!(%contract_id, "Received request to pay invoice");

    let (pay_sender, pay_receiver) = oneshot::channel::<Result<(), LnGatewayError>>();
    let gw_sender = { req.state().lock().await.clone() };

    gw_sender
        .send(GatewayRequest::PayInvoice(contract_id, pay_sender))
        .await
        .expect("failed to send over channel");
    pay_receiver.await.unwrap()?;

    Ok(Response::new(200))
}

pub async fn run_webserver(sender: mpsc::Sender<GatewayRequest>) -> tide::Result<()> {
    // Tide state must be Sync
    let sync_sender = Arc::new(Mutex::new(sender));
    let mut app = tide::with_state(sync_sender);

    app.at("/pay_invoice").post(pay_invoice);
    app.listen("127.0.0.1:8080").await?;

    Ok(())
}
