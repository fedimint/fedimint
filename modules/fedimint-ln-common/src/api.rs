use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_core::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::UnionResponses;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, NumPeers};

use crate::contracts::incoming::{IncomingContractAccount, IncomingContractOffer};
use crate::contracts::outgoing::OutgoingContractAccount;
use crate::contracts::{ContractId, FundedContract};
use crate::{ContractAccount, LightningGateway};

#[apply(async_trait_maybe_send!)]
pub trait LnFederationApi {
    async fn fetch_consensus_block_count(&self) -> FederationResult<Option<u64>>;
    async fn fetch_contract(&self, contract: ContractId) -> FederationResult<ContractAccount>;
    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer>;
    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGateway>>;
    async fn register_gateway(&self, gateway: &LightningGateway) -> FederationResult<()>;
    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool>;

    async fn get_incoming_contract(
        &self,
        id: ContractId,
    ) -> anyhow::Result<IncomingContractAccount>;

    async fn get_outgoing_contract(
        &self,
        id: ContractId,
    ) -> anyhow::Result<OutgoingContractAccount>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> LnFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn fetch_consensus_block_count(&self) -> FederationResult<Option<u64>> {
        self.request_current_consensus("block_count".to_string(), ApiRequestErased::default())
            .await
    }

    async fn fetch_contract(&self, contract: ContractId) -> FederationResult<ContractAccount> {
        self.request_current_consensus("wait_account".to_string(), ApiRequestErased::new(contract))
            .await
    }

    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer> {
        self.request_current_consensus(
            "wait_offer".to_string(),
            ApiRequestErased::new(payment_hash),
        )
        .await
    }

    /// There is no consensus within Fedimint on the gateways, each guardian
    /// might be aware of different ones, so we just return the union of all
    /// responses and allow client selection.
    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGateway>> {
        self.request_with_strategy(
            UnionResponses::new(self.all_peers().total()),
            "list_gateways".to_string(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn register_gateway(&self, gateway: &LightningGateway) -> FederationResult<()> {
        self.request_current_consensus(
            "register_gateway".to_string(),
            ApiRequestErased::new(gateway),
        )
        .await
    }

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool> {
        Ok(self
            .request_current_consensus::<Option<IncomingContractOffer>>(
                "offer".to_string(),
                ApiRequestErased::new(payment_hash),
            )
            .await?
            .is_some())
    }

    async fn get_incoming_contract(
        &self,
        id: ContractId,
    ) -> anyhow::Result<IncomingContractAccount> {
        let account = self.fetch_contract(id).await?;
        match account.contract {
            FundedContract::Incoming(c) => Ok(IncomingContractAccount {
                amount: account.amount,
                contract: c.contract,
            }),
            _ => Err(anyhow::anyhow!("WrongAccountType")),
        }
    }

    async fn get_outgoing_contract(
        &self,
        id: ContractId,
    ) -> anyhow::Result<OutgoingContractAccount> {
        let account = self.fetch_contract(id).await?;
        match account.contract {
            FundedContract::Outgoing(c) => Ok(OutgoingContractAccount {
                amount: account.amount,
                contract: c,
            }),
            _ => Err(anyhow::anyhow!("WrongAccountType")),
        }
    }
}
