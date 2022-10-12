use anyhow::Error;
use tokio::sync::{mpsc, oneshot};

use crate::{GatewayRequest, GatewayRequestTrait, Result};

#[derive(Debug, Clone)]
pub struct GatewayRpcSender {
    sender: mpsc::Sender<GatewayRequest>,
}

/// A two-way rpc channel for [`GatewayRequest`]s.
///
/// The channel consists of a long lived sender and receiver used to pass along the original message
/// And a short lived (oneshot tx, rx) is used to receive a response in the opposite direction as the original message.
impl GatewayRpcSender {
    pub fn new(sender: mpsc::Sender<GatewayRequest>) -> Self {
        Self { sender }
    }

    pub async fn send<R>(&self, message: R) -> std::result::Result<R::Response, Error>
    where
        R: GatewayRequestTrait,
    {
        let (sender, receiver) = oneshot::channel::<Result<R::Response>>();
        let msg = message.to_enum(sender);
        self.sender
            .send(msg)
            .await
            .expect("failed to send over channel");
        Ok(receiver.await.expect("Failed to send over channel")?)
    }
}
