use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::{GatewayRequest, GatewayRequestTrait, Result};

#[async_trait]
pub trait GatewayMessageReceiver: Send + Sync + 'static {
    async fn receive(&self) -> ();
}

#[derive(Debug, Clone)]
pub struct GatewayMessageChannel {
    sender: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
}

/// A two-way message channel for [`GatewayRequest`]s.
///
/// The channel consists of a long lived sender and receiver used to pass along the original message
/// And a short lived (oneshot tx, rx) is used to receive a response in the opposite direction as the original message.
impl GatewayMessageChannel {
    pub fn new(sender: &mpsc::Sender<GatewayRequest>) -> Self {
        Self {
            sender: Arc::new(Mutex::new(sender.clone().to_owned())),
        }
    }

    pub async fn send<R>(&self, message: R) -> std::result::Result<R::Response, Error>
    where
        R: GatewayRequestTrait,
    {
        let (sender, receiver) = oneshot::channel::<Result<R::Response>>();
        let msg = message.to_enum(sender);

        let gw_sender = { self.sender.lock().await.clone() };
        gw_sender
            .send(msg)
            .await
            .expect("failed to send over channel");
        Ok(receiver.await.expect("Failed to send over channel")?)
    }
}
