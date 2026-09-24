use std::num::NonZeroUsize;
use std::sync::Arc;

use fedimint_api_client::api::{DynModuleApi, FederationResult};
use fedimint_api_client::shared_cache::{SharedApiScope, SharedCache};
use fedimint_core::module::ApiVersion;
use fedimint_walletv2_common::{AWAIT_OUTPUTS_API_VERSION, OutputInfo};

use crate::api::WalletFederationApi;

/// Number of output info entries to scan per batch.
const SLICE_SIZE: u64 = 1000;

/// Whether a federation at `api_version` serves `AWAIT_OUTPUTS_ENDPOINT`.
pub(crate) fn streams_outputs(api_version: ApiVersion) -> bool {
    api_version.minor >= AWAIT_OUTPUTS_API_VERSION.minor
}

/// Shared, consensus-aggregated deposit batches.
///
/// Pass the same `Arc` through `WalletClientInit::shared_api` for each account;
/// results are keyed by federation and module instance.
/// Accounts retain their own scan cursors and claim logic.
#[derive(Debug)]
pub struct WalletV2SharedApi {
    /// Keyed by cursor, holding the outputs from there up to the returned
    /// continuation index. Only streamed batches are cached: their
    /// continuation always advances, so an entry is never re-read by the
    /// account that produced it, only by accounts at the same cursor. Entries
    /// never expire; a later reader may get fewer outputs than a fresh fetch
    /// would, but continues from the stored index and fetches fresh there.
    outputs: SharedCache<u64, (Vec<OutputInfo>, u64)>,
}

impl Default for WalletV2SharedApi {
    fn default() -> Self {
        Self {
            outputs: SharedCache::new(NonZeroUsize::new(32).expect("non-zero capacity"), None),
        }
    }
}

/// `WalletV2SharedApi` bound to one module instance.
#[derive(Debug, Clone)]
pub(crate) struct WalletV2SharedApiHandle {
    shared: Arc<WalletV2SharedApi>,
    scope: SharedApiScope,
}

impl WalletV2SharedApiHandle {
    pub(crate) fn new(shared: Arc<WalletV2SharedApi>, scope: SharedApiScope) -> Self {
        Self { shared, scope }
    }

    /// Returns at most one slice of outputs from `next_output_index` on and the
    /// index to continue from.
    ///
    /// A streaming federation blocks until an output at `next_output_index`
    /// exists and reports where the range ended, so every account's cursor is
    /// server-derived and they coincide after one round. An older federation
    /// is polled for a slice of p2wsh outputs without caching; the continuation
    /// stops at the last one because the range past it is unknown.
    pub(crate) async fn outputs_from(
        &self,
        api: &DynModuleApi,
        api_version: ApiVersion,
        next_output_index: u64,
    ) -> FederationResult<Arc<(Vec<OutputInfo>, u64)>> {
        if streams_outputs(api_version) {
            return self
                .shared
                .outputs
                .get_or_try_init(self.scope, next_output_index, || async {
                    Ok(api.await_outputs(next_output_index, SLICE_SIZE).await)
                })
                .await;
        }

        let outputs = api
            .output_info_slice(next_output_index, next_output_index + SLICE_SIZE)
            .await?;

        let next_index = outputs
            .last()
            .map_or(next_output_index, |output| output.index + 1);

        Ok(Arc::new((outputs, next_index)))
    }
}
