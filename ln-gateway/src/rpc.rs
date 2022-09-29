use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::{GatewayRequest, GatewayRequestTrait, LnGatewayError};

#[derive(Debug, Clone)]
pub struct GatewayRpcSender {
    sender: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
}

/// Oneshot GatewayRpcSender
impl GatewayRpcSender {
    pub fn new(sender: mpsc::Sender<GatewayRequest>) -> Self {
        Self {
            sender: Arc::new(Mutex::new(sender)),
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
pub trait GatewayRpcClient {
    async fn receive(&self) -> ();
}
