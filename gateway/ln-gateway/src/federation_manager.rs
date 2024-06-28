use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_core::config::FederationId;
use fedimint_core::util::Spanned;
use tokio::sync::{Mutex, RwLock};

/// The first SCID that the gateway will assign to a federation.
/// Note: This starts at 1 because an SCID of 0 is considered invalid by LND's
/// HTLC interceptor.
const INITIAL_SCID: u64 = 1;

/// Type definition for looking up a `FederationId` from a short channel id.
type ScidToFederationMap = Arc<RwLock<BTreeMap<u64, FederationId>>>;

/// Type definition for looking up a `Client` from a `FederationId`.
type FederationToClientMap =
    Arc<RwLock<BTreeMap<FederationId, Spanned<fedimint_client::ClientHandleArc>>>>;

#[derive(Debug)]
pub struct FederationManager {
    /// Map of `FederationId` -> `Client`. Used for efficient retrieval of the
    /// client while handling incoming HTLCs.
    pub clients: FederationToClientMap,

    /// Map of short channel ids to `FederationId`. Use for efficient retrieval
    /// of the client while handling incoming HTLCs.
    pub scid_to_federation: ScidToFederationMap,

    /// Tracker for short channel ID assignments. When connecting a new
    /// federation, this value is incremented and assigned to the federation
    /// as the `mint_channel_id`
    pub next_scid: Arc<Mutex<u64>>,
}

impl FederationManager {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            next_scid: Arc::new(Mutex::new(INITIAL_SCID)),
        }
    }
}
