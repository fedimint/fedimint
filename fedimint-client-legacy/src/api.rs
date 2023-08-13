pub mod fake;

use bitcoin::Address;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_core::api::{FederationApiExt, FederationResult, IFederationApi};
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::{ThresholdConsensus, UnionResponses, UnionResponsesSingle};
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
        self.with_module(LEGACY_HARDCODED_INSTANCE_ID_LN)
            .request_current_consensus("wait_account".to_string(), ApiRequestErased::new(contract))
            .await
    }
    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer> {
        self.with_module(LEGACY_HARDCODED_INSTANCE_ID_LN)
            .request_current_consensus(
                "wait_offer".to_string(),
                ApiRequestErased::new(payment_hash),
            )
            .await
    }

    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGateway>> {
        self.with_module(LEGACY_HARDCODED_INSTANCE_ID_LN)
            .request_with_strategy(
                UnionResponses::new(self.all_peers().total()),
                "list_gateways".to_string(),
                ApiRequestErased::default(),
            )
            .await
    }

    async fn register_gateway(&self, gateway: &LightningGateway) -> FederationResult<()> {
        self.with_module(LEGACY_HARDCODED_INSTANCE_ID_LN)
            .request_with_strategy(
                ThresholdConsensus::new(self.all_peers().total()),
                "register_gateway".to_string(),
                ApiRequestErased::new(gateway),
            )
            .await
    }

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool> {
        Ok(self
            .with_module(LEGACY_HARDCODED_INSTANCE_ID_LN)
            .request_current_consensus::<Option<IncomingContractOffer>>(
                "offer".to_string(),
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
        self.with_module(LEGACY_HARDCODED_INSTANCE_ID_MINT)
            .request_with_strategy(
                ThresholdConsensus::new(self.all_peers().total()),
                "backup".to_string(),
                ApiRequestErased::new(request),
            )
            .await
    }
    async fn download_ecash_backup(
        &self,
        id: &secp256k1::XOnlyPublicKey,
    ) -> FederationResult<Vec<ECashUserBackupSnapshot>> {
        Ok(self
            .with_module(LEGACY_HARDCODED_INSTANCE_ID_MINT)
            .request_with_strategy(
                UnionResponsesSingle::<Option<ECashUserBackupSnapshot>>::new(
                    self.all_peers().total(),
                ),
                "recover".to_string(),
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
    async fn fetch_consensus_block_count(&self) -> FederationResult<u64>;
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
    async fn fetch_consensus_block_count(&self) -> FederationResult<u64> {
        self.with_module(LEGACY_HARDCODED_INSTANCE_ID_WALLET)
            .request_with_strategy(
                ThresholdConsensus::new(self.all_peers().total()),
                "block_count".to_string(),
                ApiRequestErased::default(),
            )
            .await
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>> {
        self.with_module(LEGACY_HARDCODED_INSTANCE_ID_WALLET)
            .request_current_consensus(
                "peg_out_fees".to_string(),
                ApiRequestErased::new((address, amount.to_sat())),
            )
            .await
    }
}
