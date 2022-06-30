use std::sync::Arc;

use mint_client::ln::gateway::LightningGateway;
use tide::{Body, Request, Response};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

use crate::{GatewayRequest, LnGatewayError};
use minimint::modules::ln::contracts::ContractId;

type ServerState = Arc<Mutex<mpsc::Sender<GatewayRequest>>>;

#[instrument(skip_all, err)]
pub async fn pay_invoice(mut req: Request<ServerState>) -> tide::Result {
    let contract_id: ContractId = req.body_json().await?;
    debug!(%contract_id, "Received request to pay invoice");

    let (pay_sender, pay_receiver) = oneshot::channel::<Result<(), LnGatewayError>>();
    let gw_sender = { req.state().lock().await.clone() };

    gw_sender
        .send(GatewayRequest::PayInvoice((contract_id, pay_sender)))
        .await
        .expect("failed to send over channel");
    pay_receiver.await.unwrap()?;

    Ok(Response::new(200))
}

async fn info(req: Request<ServerState>) -> tide::Result {
    let (info_sender, info_receiver) = oneshot::channel::<LightningGateway>();

    let gw_sender = { req.state().lock().await.clone() };

    gw_sender
        .send(GatewayRequest::Info(info_sender))
        .await
        .expect("failed to send over channel");
    let gw_config: LightningGateway = info_receiver.await.unwrap();

    let body = Body::from_json(&gw_config).expect("encoding error");
    Ok(body.into())
}

pub async fn run_webserver(sender: mpsc::Sender<GatewayRequest>, api: String) -> tide::Result<()> {
    // Tide state needs to be Sync
    let sync_sender = Arc::new(Mutex::new(sender));
    let mut app = tide::with_state(sync_sender);

    app.at("/pay_invoice").post(pay_invoice);
    app.at("/info").get(info);
    app.listen(api).await?;

    Ok(())
}
