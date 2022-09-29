use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::{GatewayRequest, GatewayRequestTrait, LnGateway, LnGatewayError};

#[derive(Debug, Clone)]
pub struct GatewayRpcSender {
    sender: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
}

/// Oneshot GatewayRpcSender
impl GatewayRpcSender {
    pub fn new(sender: &mpsc::Sender<GatewayRequest>) -> Self {
        Self {
            sender: Arc::new(Mutex::new(sender.clone().to_owned())),
        }
    }

    pub async fn send<R>(&self, message: R) -> Result<R::Response, Error>
    where
        R: GatewayRequestTrait,
    {
        let (sender, receiver) = oneshot::channel::<Result<R::Response, LnGatewayError>>();
        let msg = message.to_enum(sender);

        let gw_sender = { self.sender.lock().await.clone() };
        gw_sender
            .send(msg)
            .await
            .expect("failed to send over channel");
        Ok(receiver.await.expect("Failed to send over channel")?)
    }
}

#[async_trait]
pub trait GatewayRpcReceiver {
    async fn receive(&mut self) -> ();
}

#[async_trait]
impl GatewayRpcReceiver for LnGateway {
    async fn receive(&mut self) {
        // Handle messages from webserver and plugin
        while let Ok(msg) = self.receiver.try_recv() {
            tracing::trace!("Gateway received message {:?}", msg);
            match msg {
                GatewayRequest::HtlcAccepted(inner) => {
                    inner
                        .handle(|htlc_accepted| self.handle_htlc_incoming_msg(htlc_accepted))
                        .await;
                }
                GatewayRequest::PayInvoice(inner) => {
                    inner
                        .handle(|contract_id| self.handle_pay_invoice_msg(contract_id))
                        .await;
                }
                GatewayRequest::Balance(inner) => {
                    inner.handle(|_| self.handle_balance_msg()).await;
                }
                GatewayRequest::DepositAddress(inner) => {
                    inner.handle(|_| self.handle_address_msg()).await;
                }
                GatewayRequest::Deposit(inner) => {
                    inner
                        .handle(|deposit| self.handle_deposit_msg(deposit))
                        .await;
                }
                GatewayRequest::Withdraw(inner) => {
                    inner
                        .handle(|withdraw| self.handle_withdraw_msg(withdraw))
                        .await;
                }
            }
        }
    }
}
