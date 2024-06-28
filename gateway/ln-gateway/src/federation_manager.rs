use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_core::config::FederationId;
use fedimint_core::util::Spanned;
use tokio::sync::{Mutex, RwLock};
use tracing::error;

use crate::{GatewayError, Result};

/// The first SCID that the gateway will assign to a federation.
/// Note: This starts at 1 because an SCID of 0 is considered invalid by LND's
/// HTLC interceptor.
const INITIAL_SCID: u64 = 1;

/// Type definition for looking up a `FederationId` from a short channel id.
type ScidToFederationMap = Arc<RwLock<BTreeMap<u64, FederationId>>>;

/// Type definition for looking up a `Client` from a `FederationId`.
type FederationToClientMap =
    Arc<RwLock<BTreeMap<FederationId, Spanned<fedimint_client::ClientHandleArc>>>>;

/// A marker struct, to distinguish lock over `FederationManager::clients`.
/// TODO(tvolk131): Make this struct private.
pub struct ClientsJoinLock;

// TODO(tvolk131): Make the fields in this struct private.
pub struct FederationManager {
    /// Map of `FederationId` -> `Client`. Used for efficient retrieval of the
    /// client while handling incoming HTLCs.
    pub clients: FederationToClientMap,

    /// Joining or leaving Federation is protected by this lock to prevent
    /// trying to use same database at the same time from multiple threads.
    /// Could be more granular (per id), but shouldn't matter in practice.
    pub client_joining_lock: Arc<tokio::sync::Mutex<ClientsJoinLock>>,

    /// Map of short channel ids to `FederationId`. Use for efficient retrieval
    /// of the client while handling incoming HTLCs.
    pub scid_to_federation: ScidToFederationMap,

    /// Tracker for short channel ID assignments. When connecting a new
    /// federation, this value is incremented and assigned to the federation
    /// as the `mint_channel_id`
    pub next_scid: Arc<Mutex<u64>>,
}

impl std::fmt::Debug for FederationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationManager")
            .field("clients", &self.clients)
            .field("scid_to_federation", &self.scid_to_federation)
            .field("next_scid", &self.next_scid)
            .finish_non_exhaustive()
    }
}

impl FederationManager {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            client_joining_lock: Arc::new(Mutex::new(ClientsJoinLock)),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            next_scid: Arc::new(Mutex::new(INITIAL_SCID)),
        }
    }

    pub async fn add_client(
        &self,
        scid: u64,
        federation_id: FederationId,
        client: Spanned<fedimint_client::ClientHandleArc>,
    ) {
        self.clients.write().await.insert(federation_id, client);
        self.scid_to_federation
            .write()
            .await
            .insert(scid, federation_id);
    }

    pub async fn remove_client(&self, federation_id: FederationId) -> Result<()> {
        let client = self
            .clients
            .write()
            .await
            .remove(&federation_id)
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))?
            .into_value();

        if let Some(client) = Arc::into_inner(client) {
            client.shutdown().await;
        } else {
            error!("client is not unique, failed to remove client");
        }

        self.scid_to_federation
            .write()
            .await
            .retain(|_, fid| *fid != federation_id);
        Ok(())
    }
}
