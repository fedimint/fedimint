use anyhow::anyhow;
use bitcoin::{Address, Amount};
use fedimint_api_client::api::{
    FederationApiExt, FederationError, FederationResult, IModuleFederationApi, ServerResult,
};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{ApiAuth, ApiRequestErased, ModuleConsensusVersion};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{NumPeersExt, PeerId, apply, async_trait_maybe_send};
use fedimint_wallet_common::endpoint_constants::{
    ACTIVATE_CONSENSUS_VERSION_VOTING_ENDPOINT, BITCOIN_KIND_ENDPOINT, BITCOIN_RPC_CONFIG_ENDPOINT,
    BLOCK_COUNT_ENDPOINT, BLOCK_COUNT_LOCAL_ENDPOINT, MODULE_CONSENSUS_VERSION_ENDPOINT,
    PEG_OUT_FEES_ENDPOINT, RECOVERY_COUNT_ENDPOINT, RECOVERY_SLICE_ENDPOINT,
    UTXO_CONFIRMED_ENDPOINT, WALLET_SUMMARY_ENDPOINT,
};
use fedimint_wallet_common::{PegOutFees, RecoveryItem, WalletSummary};

#[apply(async_trait_maybe_send!)]
pub trait WalletFederationApi {
    async fn module_consensus_version(&self) -> FederationResult<ModuleConsensusVersion>;

    async fn fetch_consensus_block_count(&self) -> FederationResult<u64>;

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: Amount,
    ) -> FederationResult<Option<PegOutFees>>;

    async fn fetch_bitcoin_rpc_kind(&self, peer_id: PeerId) -> FederationResult<String>;

    async fn fetch_bitcoin_rpc_config(&self, auth: ApiAuth) -> FederationResult<BitcoinRpcConfig>;

    async fn fetch_wallet_summary(&self) -> FederationResult<WalletSummary>;

    async fn fetch_block_count_local(&self) -> FederationResult<u32>;

    async fn is_utxo_confirmed(&self, outpoint: bitcoin::OutPoint) -> FederationResult<bool>;

    async fn activate_consensus_version_voting(&self, auth: ApiAuth) -> FederationResult<()>;

    /// Returns the total number of recovery items stored on the federation
    async fn fetch_recovery_count(&self) -> anyhow::Result<u64>;

    /// Fetches recovery items in the range `[start, end)` via consensus
    async fn fetch_recovery_slice(&self, start: u64, end: u64)
    -> anyhow::Result<Vec<RecoveryItem>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> WalletFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn module_consensus_version(&self) -> FederationResult<ModuleConsensusVersion> {
        let response = self
            .request_current_consensus(
                MODULE_CONSENSUS_VERSION_ENDPOINT.to_string(),
                ApiRequestErased::default(),
            )
            .await;

        if let Err(e) = &response
            && e.any_peer_error_method_not_found()
        {
            return Ok(ModuleConsensusVersion::new(2, 0));
        }

        response
    }

    async fn is_utxo_confirmed(&self, outpoint: bitcoin::OutPoint) -> FederationResult<bool> {
        let res = self
            .request_current_consensus(
                UTXO_CONFIRMED_ENDPOINT.to_string(),
                ApiRequestErased::new(outpoint),
            )
            .await;

        if let Err(e) = &res
            && e.any_peer_error_method_not_found()
        {
            return Ok(false);
        }

        res
    }

    async fn fetch_consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn fetch_block_count_local(&self) -> FederationResult<u32> {
        let filter_map = |_peer: PeerId, block_count: Option<u32>| -> ServerResult<Option<u32>> {
            Ok(block_count)
        };

        let block_count_responses = self
            .request_with_strategy(
                FilterMapThreshold::<Option<u32>, Option<u32>>::new(
                    filter_map,
                    self.all_peers().to_num_peers().threshold().into(),
                ),
                BLOCK_COUNT_LOCAL_ENDPOINT.to_string(),
                ApiRequestErased::default(),
            )
            .await?;

        let mut response: Vec<u32> = block_count_responses.into_values().flatten().collect();

        if response.is_empty() {
            return Err(FederationError::general(
                BLOCK_COUNT_LOCAL_ENDPOINT.to_string(),
                ApiRequestErased::default(),
                anyhow!("No valid block counts received"),
            ));
        }

        response.sort_unstable();
        let final_block_count = response[response.len() / 2];

        Ok(final_block_count)
    }

    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: Amount,
    ) -> FederationResult<Option<PegOutFees>> {
        self.request_current_consensus(
            PEG_OUT_FEES_ENDPOINT.to_string(),
            ApiRequestErased::new((address, amount.to_sat())),
        )
        .await
    }

    async fn fetch_bitcoin_rpc_kind(&self, peer_id: PeerId) -> FederationResult<String> {
        self.request_single_peer_federation(
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

    async fn fetch_wallet_summary(&self) -> FederationResult<WalletSummary> {
        self.request_current_consensus(
            WALLET_SUMMARY_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn activate_consensus_version_voting(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_admin(
            ACTIVATE_CONSENSUS_VERSION_VOTING_ENDPOINT,
            ApiRequestErased::default(),
            auth,
        )
        .await
    }

    async fn fetch_recovery_count(&self) -> anyhow::Result<u64> {
        self.request_current_consensus::<u64>(
            RECOVERY_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
        .map_err(|e| anyhow!("{e}"))
    }

    async fn fetch_recovery_slice(
        &self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Vec<RecoveryItem>> {
        self.request_current_consensus::<Vec<RecoveryItem>>(
            RECOVERY_SLICE_ENDPOINT.to_string(),
            ApiRequestErased::new((start, end)),
        )
        .await
        .map_err(|e| anyhow!("{e}"))
    }
}
