use std::collections::BTreeSet;

use bitcoin::OutPoint;
use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_walletv2_common::endpoint_constants::{
    CONSENSUS_BLOCK_COUNT_ENDPOINT, CONSENSUS_FEERATE_ENDPOINT, FEDERATION_WALLET_ENDPOINT,
    FILTER_UNSPENT_OUTPOINTS_ENDPOINT, PENDING_TRANSACTION_CHAIN_ENDPOINT, RECEIVE_FEE_ENDPOINT,
    SEND_FEE_ENDPOINT, TRANSACTION_CHAIN_ENDPOINT, TRANSACTION_INFO_ENDPOINT,
};
use fedimint_walletv2_common::{FederationWallet, ReceiveFee, SendFee, TransactionInfo};

#[apply(async_trait_maybe_send!)]
pub trait WalletFederationApi {
    async fn consensus_block_count(&self) -> FederationResult<u64>;

    async fn consensus_feerate(&self) -> FederationResult<Option<u64>>;

    async fn federation_wallet(&self) -> FederationResult<Option<FederationWallet>>;

    async fn send_fee(&self) -> FederationResult<Option<SendFee>>;

    async fn receive_fee(&self) -> FederationResult<Option<ReceiveFee>>;

    async fn pending_transaction_chain(&self) -> FederationResult<Vec<TransactionInfo>>;

    async fn transaction_info(&self, index: u64) -> FederationResult<Option<TransactionInfo>>;

    async fn transaction_chain(&self, n: usize) -> FederationResult<Vec<TransactionInfo>>;

    async fn filter_unspent_outpoints(
        &self,
        outpoints: &BTreeSet<OutPoint>,
    ) -> FederationResult<BTreeSet<OutPoint>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> WalletFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            CONSENSUS_BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn consensus_feerate(&self) -> FederationResult<Option<u64>> {
        self.request_current_consensus(
            CONSENSUS_FEERATE_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn federation_wallet(&self) -> FederationResult<Option<FederationWallet>> {
        self.request_current_consensus(
            FEDERATION_WALLET_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn send_fee(&self) -> FederationResult<Option<SendFee>> {
        self.request_current_consensus(SEND_FEE_ENDPOINT.to_string(), ApiRequestErased::new(()))
            .await
    }

    async fn receive_fee(&self) -> FederationResult<Option<ReceiveFee>> {
        self.request_current_consensus(RECEIVE_FEE_ENDPOINT.to_string(), ApiRequestErased::new(()))
            .await
    }

    async fn pending_transaction_chain(&self) -> FederationResult<Vec<TransactionInfo>> {
        self.request_current_consensus(
            PENDING_TRANSACTION_CHAIN_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn transaction_info(&self, index: u64) -> FederationResult<Option<TransactionInfo>> {
        self.request_current_consensus(
            TRANSACTION_INFO_ENDPOINT.to_string(),
            ApiRequestErased::new(index),
        )
        .await
    }

    async fn transaction_chain(&self, n: usize) -> FederationResult<Vec<TransactionInfo>> {
        self.request_current_consensus(
            TRANSACTION_CHAIN_ENDPOINT.to_string(),
            ApiRequestErased::new(n),
        )
        .await
    }

    async fn filter_unspent_outpoints(
        &self,
        outpoints: &BTreeSet<OutPoint>,
    ) -> FederationResult<BTreeSet<OutPoint>> {
        self.request_current_consensus(
            FILTER_UNSPENT_OUTPOINTS_ENDPOINT.to_string(),
            ApiRequestErased::new(outpoints),
        )
        .await
    }
}
