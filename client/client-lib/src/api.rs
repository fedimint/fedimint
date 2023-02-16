pub mod fake;

use async_trait::async_trait;
use bitcoin::Address;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use fedimint_core::api::{
    erased_multi_param, erased_no_param, erased_single_param, FederationApiExt, FederationResult,
    IFederationApi,
};
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::query::{
    CurrentConsensus, EventuallyConsistent, Retry404, UnionResponses, UnionResponsesSingle,
};
use fedimint_core::NumPeers;
use fedimint_mint::db::ECashUserBackupSnapshot;

use crate::modules::ln::contracts::incoming::IncomingContractOffer;
use crate::modules::ln::contracts::ContractId;
use crate::modules::ln::{ContractAccount, LightningGateway};
use crate::modules::wallet::PegOutFees;

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
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

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T: ?Sized> LnFederationApi for T
where
    T: IFederationApi + Send + Sync + 'static,
{
    async fn fetch_contract(&self, contract: ContractId) -> FederationResult<ContractAccount> {
        self.request_with_strategy(
            Retry404::new(self.all_members().one_honest()),
            format!("/module/{LEGACY_HARDCODED_INSTANCE_ID_LN}/account"),
            erased_single_param(&contract),
        )
        .await
    }
    async fn fetch_offer(
        &self,
        payment_hash: Sha256Hash,
    ) -> FederationResult<IncomingContractOffer> {
        self.request_with_strategy(
            Retry404::new(self.all_members().one_honest()),
            format!("/module/{LEGACY_HARDCODED_INSTANCE_ID_LN}/offer"),
            erased_single_param(&payment_hash),
        )
        .await
    }

    async fn fetch_gateways(&self) -> FederationResult<Vec<LightningGateway>> {
        self.request_with_strategy(
            UnionResponses::new(self.all_members().threshold()),
            format!("/module/{LEGACY_HARDCODED_INSTANCE_ID_LN}/list_gateways"),
            erased_no_param(),
        )
        .await
    }

    async fn register_gateway(&self, gateway: &LightningGateway) -> FederationResult<()> {
        self.request_with_strategy(
            CurrentConsensus::new(self.all_members().threshold()),
            format!("/module/{LEGACY_HARDCODED_INSTANCE_ID_LN}/register_gateway"),
            erased_single_param(gateway),
        )
        .await
    }

    async fn offer_exists(&self, payment_hash: Sha256Hash) -> FederationResult<bool> {
        match self.fetch_offer(payment_hash).await {
            Ok(_) => Ok(true),
            Err(e) if e.is_retryable() => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait MintFederationApi {
    async fn upload_ecash_backup(
        &self,
        request: &fedimint_mint::SignedBackupRequest,
    ) -> FederationResult<()>;
    async fn download_ecash_backup(
        &self,
        id: &secp256k1::XOnlyPublicKey,
    ) -> FederationResult<Vec<ECashUserBackupSnapshot>>;
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T: ?Sized> MintFederationApi for T
where
    T: IFederationApi + Send + Sync + 'static,
{
    async fn upload_ecash_backup(
        &self,
        request: &fedimint_mint::SignedBackupRequest,
    ) -> FederationResult<()> {
        self.request_with_strategy(
            CurrentConsensus::new(self.all_members().threshold()),
            format!("/module/{LEGACY_HARDCODED_INSTANCE_ID_MINT}/backup"),
            erased_single_param(request),
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
                format!("/module/{LEGACY_HARDCODED_INSTANCE_ID_MINT}/recover"),
                erased_single_param(id),
            )
            .await?
            .into_iter()
            .flatten()
            .collect())
    }
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait WalletFederationApi {
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64>;
    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>>;
}

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T: ?Sized> WalletFederationApi for T
where
    T: IFederationApi + Send + Sync + 'static,
{
    async fn fetch_consensus_block_height(&self) -> FederationResult<u64> {
        self.request_with_strategy(
            EventuallyConsistent::new(self.all_members().one_honest()),
            format!("/module/{LEGACY_HARDCODED_INSTANCE_ID_WALLET}/block_height"),
            erased_no_param(),
        )
        .await
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>> {
        self.request_eventually_consistent(
            format!("/module/{LEGACY_HARDCODED_INSTANCE_ID_WALLET}/peg_out_fees"),
            erased_multi_param(&(address, amount.to_sat())),
        )
        .await
    }
}
