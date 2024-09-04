use std::time::Duration;

use bitcoin::Address;
use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, PeerId};
use fedimint_wallet_common::endpoint_constants::{
    BITCOIN_KIND_ENDPOINT, BITCOIN_RPC_CONFIG_ENDPOINT, BLOCK_COUNT_ENDPOINT, PEG_OUT_FEES_ENDPOINT,
};
use fedimint_wallet_common::PegOutFees;

#[apply(async_trait_maybe_send!)]
pub trait WalletFederationApi {
    async fn fetch_consensus_block_count(&self) -> FederationResult<u64>;

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>>;

    async fn fetch_bitcoin_rpc_kind(&self, peer_id: PeerId) -> FederationResult<String>;

    async fn fetch_bitcoin_rpc_config(&self, auth: ApiAuth) -> FederationResult<BitcoinRpcConfig>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> WalletFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn fetch_consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> FederationResult<Option<PegOutFees>> {
        self.request_current_consensus(
            PEG_OUT_FEES_ENDPOINT.to_string(),
            ApiRequestErased::new((address, amount.to_sat())),
        )
        .await
    }

    async fn fetch_bitcoin_rpc_kind(&self, peer_id: PeerId) -> FederationResult<String> {
        self.request_single_peer_federation(
            Some(Duration::from_secs(10)),
            BITCOIN_KIND_ENDPOINT.to_string(),
            ApiRequestErased::default(),
            peer_id,
        )
        .await
    }

    async fn fetch_bitcoin_rpc_config(&self, auth: ApiAuth) -> FederationResult<BitcoinRpcConfig> {
        self.request_admin(
            BITCOIN_RPC_CONFIG_ENDPOINT,
            ApiRequestErased::default(),
            auth,
        )
        .await
    }
}
