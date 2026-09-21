use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin_hashes::sha256;
use fedimint_api_client::api::DynModuleApi;
use fedimint_api_client::shared_cache::{SharedApiScope, SharedCache};
use fedimint_core::PeerId;
use fedimint_core::encoding::Encodable;
use fedimint_core::util::backoff_util::custom_backoff;
use fedimint_mintv2_common::RecoveryItem;

use crate::api::MintV2ModuleApi;

/// Recovery history is fetched in fixed strides from index 0, so every account
/// requests the same slices and can share them.
pub(crate) const SLICE_SIZE: u64 = 10000;
/// How long a guardian sits out after failing to answer a slice request.
const PEER_READMISSION: Duration = Duration::from_secs(60);
/// How long a single peer is given to answer a slice request.
///
/// A slice takes a second or two from a healthy guardian, so waiting half a
/// minute only delays noticing that one is not going to answer. The timeout
/// grows on every failed attempt up to [`MAX_SLICE_TIMEOUT`], so a client
/// on a slow connection where every guardian exceeds the initial timeout
/// still makes progress instead of retrying forever.
const SLICE_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for the per-retry growth of [`SLICE_TIMEOUT`]; the flat
/// timeout used before the growth was introduced.
const MAX_SLICE_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared, hash-verified recovery history.
///
/// Pass the same `Arc` through `MintClientInit::shared_api` for each account;
/// results are keyed by federation and module instance. Only public recovery
/// items are shared; note reconstruction stays account-local. Recovery counts
/// are deliberately fetched fresh when starting a recovery.
#[derive(Debug)]
pub struct MintV2SharedApi {
    /// Keyed by the half-open item range of a slice, `slice * SLICE_SIZE` up
    /// to the next stride or the recovery's item count, whichever is lower.
    /// Slices are hash-verified and history only grows, so entries never
    /// expire. Only the final, partial slice depends on when a recovery began.
    slices: SharedCache<(u64, u64), Vec<RecoveryItem>>,
    /// One pool per federation, so concurrent recoveries of several accounts
    /// together keep at most one slice request outstanding per guardian.
    peers: RwLock<BTreeMap<SharedApiScope, PeerPool>>,
}

impl Default for MintV2SharedApi {
    fn default() -> Self {
        Self {
            slices: SharedCache::new(NonZeroUsize::new(32).expect("non-zero capacity"), None),
            peers: RwLock::new(BTreeMap::new()),
        }
    }
}

/// `MintV2SharedApi` bound to one module instance.
#[derive(Debug, Clone)]
pub(crate) struct MintV2SharedApiHandle {
    shared: Arc<MintV2SharedApi>,
    scope: SharedApiScope,
}

impl MintV2SharedApiHandle {
    pub(crate) fn new(shared: Arc<MintV2SharedApi>, scope: SharedApiScope) -> Self {
        Self { shared, scope }
    }

    /// Fetches slice number `slice` of a history holding `total_items` items.
    pub(crate) async fn verified_recovery_slice(
        &self,
        api: &DynModuleApi,
        slice: u64,
        total_items: u64,
    ) -> Arc<Vec<RecoveryItem>> {
        let start = slice * SLICE_SIZE;
        let end = (start + SLICE_SIZE).min(total_items);

        self.shared
            .slices
            .get_or_try_init(self.scope, (start, end), || async {
                let hash = api.fetch_recovery_slice_hash(start, end).await;
                let peers = self.shared.peer_pool(self.scope, api.all_peers());
                Ok::<_, Infallible>(download_slice(api.clone(), peers, start, end, hash).await)
            })
            .await
            .expect("verified recovery download retries indefinitely")
    }
}

impl MintV2SharedApi {
    fn peer_pool(&self, scope: SharedApiScope, peers: &BTreeSet<PeerId>) -> PeerPool {
        if let Some(pool) = self
            .peers
            .read()
            .expect("peer pools lock poisoned")
            .get(&scope)
        {
            return pool.clone();
        }
        self.peers
            .write()
            .expect("peer pools lock poisoned")
            .entry(scope)
            .or_insert_with(|| PeerPool::new(peers))
            .clone()
    }
}

/// Hands out guardians so that only one slice request is outstanding to each.
///
/// Whichever peer finishes first takes the next slice, so a slow guardian
/// receives less work without anyone having to measure how slow it is, and one
/// that is not answering ties up a single request rather than a share of all
/// of them.
#[derive(Debug, Clone)]
struct PeerPool {
    receiver: async_channel::Receiver<PeerId>,
    sender: async_channel::Sender<PeerId>,
}

impl PeerPool {
    fn new(peers: &BTreeSet<PeerId>) -> Self {
        let (sender, receiver) = async_channel::bounded(peers.len().max(1));

        for peer in peers {
            sender
                .try_send(*peer)
                .expect("Capacity was sized to hold every peer");
        }

        Self { receiver, sender }
    }

    /// Wait for a guardian with no request outstanding.
    async fn acquire(&self) -> PeerId {
        self.receiver
            .recv()
            .await
            .expect("The sender is held for as long as the receiver")
    }

    /// Take a guardian out of rotation, putting it back once it has sat out
    /// [`PEER_READMISSION`].
    ///
    /// Dropping it for good would cost a guardian that timed out once the rest
    /// of the recovery, which on a federation of four is a quarter of the
    /// capacity thrown away for a single bad request.
    fn retire(&self, peer: PeerId) {
        let pool = self.clone();

        fedimint_core::runtime::spawn("mintv2 recovery peer readmission", async move {
            fedimint_core::runtime::sleep(PEER_READMISSION).await;

            pool.release(peer);
        });
    }

    /// Put a guardian back for the next slice.
    fn release(&self, peer: PeerId) {
        self.sender
            .try_send(peer)
            .expect("Only peers taken from the pool are put back");
    }
}

/// Download a slice, asking one guardian at a time and holding it for the
/// duration of the request.
async fn download_slice(
    module_api: DynModuleApi,
    peers: PeerPool,
    start: u64,
    end: u64,
    expected_hash: sha256::Hash,
) -> Vec<RecoveryItem> {
    let mut timeouts = custom_backoff(SLICE_TIMEOUT, MAX_SLICE_TIMEOUT, None);

    loop {
        let peer = peers.acquire().await;

        let timeout = timeouts.next().expect("The backoff never gives up");

        let result = module_api
            .fetch_recovery_slice(peer, timeout, start, end)
            .await;

        match result {
            Ok(data) if data.consensus_hash::<sha256::Hash>() == expected_hash => {
                peers.release(peer);

                return data;
            }
            // Either served something the other guardians disagree with, or
            // did not answer at all. Either way it sits out for a while: a
            // request that reaches the timeout took many times longer than a
            // healthy guardian needs, so asking it again mostly buys another
            // timeout. The timeout grows in case it is the client's own
            // connection that is too slow for the initial one.
            Ok(_) | Err(_) => peers.retire(peer),
        }
    }
}
