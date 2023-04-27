use fedimint_core::api::{FederationApiExt, FederationResult, IFederationApi};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_LN;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::{CurrentConsensus, UnionResponses};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, NumPeers};
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::ContractId;
use fedimint_ln_common::{ContractAccount, LightningGateway};

use crate::Sha256Hash;

#[apply(async_trait_maybe_send!)]
pub trait LnFederationApi {
    async fn fetch_contract(&self, contract: ContractId) -> FederationResult<ContractAccount>;
    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer>;
    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGateway>>;
    async fn register_gateway(&self, gateway: &LightningGateway) -> FederationResult<()>;
    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> LnFederationApi for T
where
    T: IFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn fetch_contract(&self, contract: ContractId) -> FederationResult<ContractAccount> {
        self.request_current_consensus(
            format!("module_{LEGACY_HARDCODED_INSTANCE_ID_LN}_wait_account"),
            ApiRequestErased::new(contract),
        )
        .await
    }
    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer> {
        self.request_current_consensus(
            format!("module_{LEGACY_HARDCODED_INSTANCE_ID_LN}_wait_offer"),
            ApiRequestErased::new(payment_hash),
        )
        .await
    }

    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGateway>> {
        self.request_with_strategy(
            UnionResponses::new(self.all_members().threshold()),
            format!("module_{LEGACY_HARDCODED_INSTANCE_ID_LN}_list_gateways"),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn register_gateway(&self, gateway: &LightningGateway) -> FederationResult<()> {
        self.request_with_strategy(
            CurrentConsensus::new(self.all_members().threshold()),
            format!("module_{LEGACY_HARDCODED_INSTANCE_ID_LN}_register_gateway"),
            ApiRequestErased::new(gateway),
        )
        .await
    }

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool> {
        Ok(self
            .request_current_consensus::<Option<IncomingContractOffer>>(
                format!("module_{LEGACY_HARDCODED_INSTANCE_ID_LN}_offer"),
                ApiRequestErased::new(payment_hash),
            )
            .await?
            .is_some())
    }
}
