use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use fedimint_api_client::api::{DynModuleApi, FederationApiExt, FederationResult};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_api_client::shared_cache::{SharedApiScope, SharedCache};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::util::SafeUrl;
use fedimint_core::{NumPeersExt, PeerId};
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::endpoint_constants::GATEWAYS_ENDPOINT;
use rand::seq::SliceRandom;

use crate::api::LightningFederationApi;

/// Shared receive snapshots and gateway discovery.
///
/// Pass the same `Arc` through `LightningClientInit::shared_api` for each
/// account; results are keyed by federation and module instance. Each account
/// retains its cursor, key matching, and claim state machines.
#[derive(Debug)]
pub struct LightningV2SharedApi {
    /// Keyed by `(start, n)`, holding the contracts from `start` and the
    /// server-reported continuation index. The server answers once the stream
    /// head passes `start`, so entries are immutable and never expire.
    incoming: SharedCache<(u64, usize), (Vec<IncomingContract>, u64)>,
    /// The gateway list changes as gateways register and leave, so it expires;
    /// the TTL also rate-limits discovery, which runs on every payment.
    gateways: SharedCache<(), Vec<(SafeUrl, usize)>>,
}

impl Default for LightningV2SharedApi {
    fn default() -> Self {
        Self {
            incoming: SharedCache::new(NonZeroUsize::new(32).expect("non-zero capacity"), None),
            gateways: SharedCache::new(
                NonZeroUsize::new(1).expect("non-zero capacity"),
                Some(Duration::from_secs(60)),
            ),
        }
    }
}

/// `LightningV2SharedApi` bound to one module instance.
#[derive(Debug, Clone)]
pub(crate) struct LightningV2SharedApiHandle {
    shared: Arc<LightningV2SharedApi>,
    scope: SharedApiScope,
}

impl LightningV2SharedApiHandle {
    pub(crate) fn new(shared: Arc<LightningV2SharedApi>, scope: SharedApiScope) -> Self {
        Self { shared, scope }
    }

    pub(crate) async fn await_incoming_contracts(
        &self,
        api: &DynModuleApi,
        start: u64,
        n: usize,
    ) -> Arc<(Vec<IncomingContract>, u64)> {
        self.shared
            .incoming
            .get_or_try_init(self.scope, (start, n), || async {
                Ok::<_, Infallible>(api.await_incoming_contracts(start, n).await)
            })
            .await
            .expect("incoming contract API retries indefinitely")
    }

    pub(crate) async fn gateways(&self, api: &DynModuleApi) -> FederationResult<Vec<SafeUrl>> {
        let gateways = self
            .shared
            .gateways
            .get_or_try_init(self.scope, (), || async {
                let responses: BTreeMap<PeerId, Vec<SafeUrl>> = api
                    .request_with_strategy(
                        FilterMapThreshold::new(
                            |_, gateways| Ok(gateways),
                            api.all_peers().to_num_peers(),
                        ),
                        GATEWAYS_ENDPOINT.to_string(),
                        ApiRequestErased::default(),
                    )
                    .await?;
                // Cache only the union and support counts, not guardian responses.
                Ok(responses
                    .values()
                    .flatten()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|url| {
                        let missing = responses.values().filter(|r| !r.contains(&url)).count();
                        (url, missing)
                    })
                    .collect())
            })
            .await?;

        // Preserve payment distribution: randomize ties for every caller, even
        // when discovery was served from the cache.
        let mut gateways = gateways.as_ref().clone();
        gateways.shuffle(&mut rand::thread_rng());
        gateways.sort_by_key(|(_, missing)| *missing);
        Ok(gateways.into_iter().map(|(url, _)| url).collect())
    }
}
