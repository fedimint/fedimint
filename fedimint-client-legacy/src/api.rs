pub mod fake;

use bitcoin::Address;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_core::api::{FederationApiExt, FederationResult, IFederationApi};
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::{
    CurrentConsensus, EventuallyConsistent, UnionResponses, UnionResponsesSingle,
};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, NumPeers};
use fedimint_mint_client::common::db::ECashUserBackupSnapshot;

use crate::modules::ln::contracts::incoming::IncomingContractOffer;
use crate::modules::ln::contracts::ContractId;
use crate::modules::ln::{ContractAccount, LightningGateway};
use crate::modules::wallet::PegOutFees;

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

#[apply(async_trait_maybe_send!)]
pub trait MintFederationApi {
    async fn upload_ecash_backup(
        &self,
        request: &fedimint_mint_client::SignedBackupRequest,
    ) -> FederationResult<()>;
    async fn download_ecash_backup(
        &self,
        id: &secp256k1::XOnlyPublicKey,
    ) -> FederationResult<Vec<ECashUserBackupSnapshot>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> MintFederationApi for T
where
    T: IFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn upload_ecash_backup(
        &self,
        request: &fedimint_mint_client::SignedBackupRequest,
    ) -> FederationResult<()> {
        self.request_with_strategy(
            CurrentConsensus::new(self.all_members().threshold()),
            format!("module_{LEGACY_HARDCODED_INSTANCE_ID_MINT}_backup"),
            ApiRequestErased::new(request),
        )
        .await
    }
    async fn download_ecash_backup(
        &self,
        id: &secp256k1::XOnlyPublicKey,
    ) -> FederationResult<Vec<ECashUserBackupSnapshot>> {
        Ok(self
            .request_with_strategy(
                UnionResponsesSingle::<Option<ECashUserBackupSnapshot>>::new(
                    self.all_members().threshold(),
                ),
                format!("module_{LEGACY_HARDCODED_INSTANCE_ID_MINT}_recover"),
                ApiRequestErased::new(id),
            )
            .await?
            .into_iter()
            .flatten()
            .collect())
    }
}

#[apply(async_trait_maybe_send!)]
pub trait WalletFederationApi {
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64>;
    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> WalletFederationApi for T
where
    T: IFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64> {
        self.request_with_strategy(
            EventuallyConsistent::new(self.all_members().one_honest()),
            format!("module_{LEGACY_HARDCODED_INSTANCE_ID_WALLET}_block_height"),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>> {
        self.request_eventually_consistent(
            format!("module_{LEGACY_HARDCODED_INSTANCE_ID_WALLET}_peg_out_fees"),
            ApiRequestErased::new((address, amount.to_sat())),
        )
        .await
    }
}
