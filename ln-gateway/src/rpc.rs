use async_trait::async_trait;
use bitcoin::Address;
use fedimint_api::{Amount, TransactionId};
use fedimint_server::modules::ln::contracts::{ContractId, Preimage};
use tokio::sync::mpsc;

use crate::{
    cln::HtlcAccepted, BalancePayload, DepositAddressPayload, DepositPayload, GatewayRequest,
    Result, WithdrawPayload,
};

#[async_trait]
pub trait GatewayRpc: Send + Sync + 'static {
    async fn htlc_accepted(&self, msg: HtlcAccepted) -> Result<Preimage>;
    async fn pay_invoice(&self, msg: ContractId) -> Result<()>;
    async fn balance(&self, msg: BalancePayload) -> Result<Amount>;
    async fn deposit_address(&self, msg: DepositAddressPayload) -> Result<Address>;
    async fn deposit(&self, msg: DepositPayload) -> Result<TransactionId>;
    async fn withdraw(&self, msg: WithdrawPayload) -> Result<TransactionId>;
}

pub struct NullGatewayRpc {}

impl NullGatewayRpc {
    fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl GatewayRpc for NullGatewayRpc {
    async fn htlc_accepted(&self, _msg: HtlcAccepted) -> Result<Preimage> {
        unimplemented!("NullGatewayRpc::htlc_accepted")
    }

    async fn pay_invoice(&self, _msg: ContractId) -> Result<()> {
        unimplemented!("NullGatewayRpc::pay_invoice")
    }

    async fn balance(&self, _msg: BalancePayload) -> Result<Amount> {
        unimplemented!("NullGatewayRpc::balance")
    }

    async fn deposit_address(&self, _msg: DepositAddressPayload) -> Result<Address> {
        unimplemented!("NullGatewayRpc::deposit_address")
    }

    async fn deposit(&self, _msg: DepositPayload) -> Result<TransactionId> {
        unimplemented!("NullGatewayRpc::deposit")
    }

    async fn withdraw(&self, _msg: WithdrawPayload) -> Result<TransactionId> {
        unimplemented!("NullGatewayRpc::withdraw")
    }
}

pub struct RealGatewayRpc {
    receiver: mpsc::Receiver<GatewayRequest>,
}

impl RealGatewayRpc {
    fn new(receiver: &mpsc::Receiver<GatewayRequest>) -> Self {
        Self { receiver }
    }
}

#[async_trait]
impl GatewayRpc for RealGatewayRpc {
    async fn htlc_accepted(&self, _msg: HtlcAccepted) -> Result<Preimage> {
        unimplemented!("NullGatewayRpc::htlc_accepted")
    }

    async fn pay_invoice(&self, _msg: ContractId) -> Result<()> {
        unimplemented!("NullGatewayRpc::pay_invoice")
    }

    async fn balance(&self, _msg: BalancePayload) -> Result<Amount> {
        unimplemented!("NullGatewayRpc::balance")
    }

    async fn deposit_address(&self, _msg: DepositAddressPayload) -> Result<Address> {
        unimplemented!("NullGatewayRpc::deposit_address")
    }

    async fn deposit(&self, _msg: DepositPayload) -> Result<TransactionId> {
        unimplemented!("NullGatewayRpc::deposit")
    }

    async fn withdraw(&self, _msg: WithdrawPayload) -> Result<TransactionId> {
        unimplemented!("NullGatewayRpc::withdraw")
    }
}
