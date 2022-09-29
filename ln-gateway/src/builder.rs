use crate::LnGatewayError;
use crate::{ln::LnRpc, rpc::GatewayRpc, GatewayRequest};
use bitcoin_hashes::sha256;
use fedimint_api::{Amount, OutPoint};
use fedimint_server::modules::ln::contracts::{ContractId, Preimage};
use futures::Future;
use mint_client::GatewayClient;
use rand::{CryptoRng, RngCore};
use std::fmt::{Display, Formatter};
use std::{result::Result, sync::Arc};
use thiserror::Error;
use tokio::sync::mpsc;

pub struct Gateway {
    lightning_rpc: Arc<dyn LnRpc>,
    gateway_rpc: Arc<dyn GatewayRpc>,
    gateway_client: Arc<GatewayClient>,
}

#[derive(Debug)]
pub enum GatewayBuilderState {
    AwaitingLightningRpc(mpsc::Sender<GatewayRequest>),
    AwaitingGatewayRpc(mpsc::Receiver<GatewayRequest>),
    AwaitingGatewayClient,
    Ready,
}

pub struct GatewayBuilder {
    pub state: GatewayBuilderState,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
    lightning_rpc: Option<Arc<dyn LnRpc>>,
    gateway_rpc: Option<Arc<dyn GatewayRpc>>,
    gateway_client: Option<Arc<GatewayClient>>,
}

pub type BuildResult<T> = std::result::Result<T, GatewayBuilderError>;

impl GatewayBuilder {
    pub fn new() -> Self {
        let (sender, receiver): (mpsc::Sender<GatewayRequest>, mpsc::Receiver<GatewayRequest>) =
            mpsc::channel(100);

        Self {
            sender,
            receiver,
            state: GatewayBuilderState::AwaitingLightningRpc(sender.clone()),
            lightning_rpc: None,
            gateway_rpc: None,
            gateway_client: None,
        }
    }

    fn suggest_next_state(&self) -> GatewayBuilderState {
        if self.lightning_rpc.is_none() {
            GatewayBuilderState::AwaitingLightningRpc(self.sender)
        } else if self.gateway_client.is_none() {
            GatewayBuilderState::AwaitingGatewayClient
        } else if self.gateway_rpc.is_none() {
            GatewayBuilderState::AwaitingGatewayRpc(self.receiver)
        } else {
            GatewayBuilderState::Ready
        }
    }

    pub async fn with_lightning_rpc<F, T>(mut self, build_lightning_rpc: F) -> Self
    where
        F: FnOnce(mpsc::Sender<GatewayRequest>) -> T,
        T: Future<Output = Result<Arc<dyn LnRpc>, GatewayBuilderError>>,
    {
        if let Ok(lightning_rpc) = build_lightning_rpc(self.sender.clone()).await {
            self.lightning_rpc = Some(lightning_rpc);
            self.state = self.suggest_next_state();
        }
        self
    }

    pub async fn with_gateway_rpc<F, T>(mut self, build_gateway_rpc: F) -> Self
    where
        F: FnOnce(mpsc::Receiver<GatewayRequest>) -> T,
        T: Future<Output = Result<Arc<dyn GatewayRpc>, GatewayBuilderError>>,
    {
        if let Ok(gateway_rpc) = build_gateway_rpc(self.receiver).await {
            self.gateway_rpc = Some(gateway_rpc);
            self.state = self.suggest_next_state();
        }
        self
    }

    pub fn with_gateway_client(mut self, gateway_client: Arc<GatewayClient>) -> Self {
        self.gateway_client = Some(gateway_client);
        self.state = GatewayBuilderState::Ready;
        self
    }

    pub fn build(&self) -> BuildResult<Gateway> {
        match self.state {
            GatewayBuilderState::Ready => {
                let lightning_rpc = self
                    .lightning_rpc
                    .ok_or_else(|| BuilderError(GatewayBuilderError::LightningRpcNotSet))
                    .expect("cannot build gateway without lightning rpc");
                let gateway_rpc = self
                    .gateway_rpc
                    .ok_or_else(|| BuilderError(GatewayBuilderError::GatewayRpcNotSet))
                    .expect("cannot build gateway without gateway rpc");
                let gateway_client = self
                    .gateway_client
                    .ok_or_else(|| BuilderError(GatewayBuilderError::GatewayClientNotSet))
                    .expect("cannot build gateway without gateway client");

                Ok(Gateway {
                    lightning_rpc,
                    gateway_rpc,
                    gateway_client,
                })
            }
            _ => Err(GatewayBuilderError::BuilderNotReady),
        }
    }
}

impl Gateway {
    pub async fn buy_preimage_offer(
        &self,
        payment_hash: &sha256::Hash,
        amount: &Amount,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(OutPoint, ContractId), LnGatewayError> {
        let (outpoint, contract_id) = self
            .gateway_client
            .buy_preimage_offer(payment_hash, amount, rng)
            .await?;
        Ok((outpoint, contract_id))
    }

    pub async fn await_preimage_decryption(
        &self,
        outpoint: OutPoint,
    ) -> Result<Preimage, LnGatewayError> {
        let preimage = self
            .gateway_client
            .await_preimage_decryption(outpoint)
            .await?;
        Ok(preimage)
    }
}

#[derive(Debug, Error)]
pub enum GatewayBuilderError {
    #[error("GatewayBuilder is not ready")]
    BuilderNotReady,
    #[error("Lightning RPC not set")]
    LightningRpcNotSet,
    #[error("Gateway RPC not set")]
    GatewayRpcNotSet,
    #[error("Gateway client not set")]
    GatewayClientNotSet,
}

#[derive(Debug, Error)]
pub struct BuilderError(#[from] GatewayBuilderError);

impl Display for BuilderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {}", self.0)
    }
}
