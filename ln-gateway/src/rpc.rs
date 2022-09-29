use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use bitcoin::Address;
use fedimint_api::{Amount, TransactionId};
use fedimint_server::modules::ln::contracts::{ContractId, Preimage};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::{
    cln::HtlcAccepted, BalancePayload, DepositAddressPayload, DepositPayload, GatewayRequest,
    GatewayRequestTrait, LnGatewayError, Result, WithdrawPayload,
};

#[async_trait]
pub trait GatewayRpcApi: Send + Sync + 'static {
    async fn htlc_accepted(&self, msg: HtlcAccepted) -> Result<Preimage>;
    async fn pay_invoice(&self, msg: ContractId) -> Result<()>;
    async fn balance(&self, msg: BalancePayload) -> Result<Amount>;
    async fn deposit_address(&self, msg: DepositAddressPayload) -> Result<Address>;
    async fn deposit(&self, msg: DepositPayload) -> Result<TransactionId>;
    async fn withdraw(&self, msg: WithdrawPayload) -> Result<TransactionId>;
}

pub struct GatewayRpc {
    sender: mpsc::Sender<GatewayRequest>,
}

impl GatewayRpc {
    fn new(sender: mpsc::Sender<GatewayRequest>) -> Self {
        Self { sender }
    }

    async fn rpc_send<R>(
        &self,
        sender_mx: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
        message: R,
    ) -> Result<R::Response, Error>
    where
        R: GatewayRequestTrait,
    {
        let (sender, receiver) = oneshot::channel::<Result<R::Response, LnGatewayError>>();
        let gw_sender = { sender_mx.lock().await.clone() };
        let msg = message.to_enum(sender);
        gw_sender
            .send(msg)
            .await
            .expect("failed to send over channel");
        Ok(receiver.await.expect("Failed to send over channel")?)
    }
}

#[async_trait]
impl GatewayRpcApi for GatewayRpc {
    async fn htlc_accepted(
        &self,
        sender_mx: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
        message: HtlcAccepted,
    ) -> Result<Preimage> {
        self.rpc_send(sender_mx, message)
    }

    async fn pay_invoice(
        &self,
        sender_mx: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
        message: ContractId,
    ) -> Result<()> {
        self.rpc_send(sender_mx, message)
    }

    async fn balance(
        &self,
        sender_mx: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
        message: BalancePayload,
    ) -> Result<Amount> {
        self.rpc_send(sender_mx, message)
    }

    async fn deposit_address(
        &self,
        sender_mx: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
        message: DepositAddressPayload,
    ) -> Result<Address> {
        self.rpc_send(sender_mx, message)
    }

    async fn deposit(
        &self,
        sender_mx: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
        message: DepositPayload,
    ) -> Result<TransactionId> {
        self.rpc_send(sender_mx, message)
    }

    async fn withdraw(
        &self,
        sender_mx: Arc<Mutex<mpsc::Sender<GatewayRequest>>>,
        message: WithdrawPayload,
    ) -> Result<TransactionId> {
        self.rpc_send(sender_mx, message)
    }
}
