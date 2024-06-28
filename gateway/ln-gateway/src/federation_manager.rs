use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_client::ClientHandleArc;
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

#[derive(Debug)]
pub struct FederationManager {
    /// Map of `FederationId` -> `Client`. Used for efficient retrieval of the
    /// client while handling incoming HTLCs.
    pub clients: FederationToClientMap,

    /// Map of short channel ids to `FederationId`. Use for efficient retrieval
    /// of the client while handling incoming HTLCs.
    scid_to_federation: ScidToFederationMap,

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

    pub async fn is_empty(&self) -> bool {
        self.clients.read().await.is_empty()
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

    pub async fn get_client_for_scid(
        &self,
        short_channel_id: u64,
    ) -> Option<Spanned<ClientHandleArc>> {
        let scid_to_feds = self.scid_to_federation.read().await;
        let clients = self.clients.read().await;

        let federation_id = scid_to_feds.get(&short_channel_id)?;
        // TODO(tvolk131): Cloning the client here could cause issues with client
        // shutdown (see `remove_client` above). Perhaps this function should take a
        // lambda and pass it into `client.with_sync`.
        if let Some(client) = clients.get(federation_id).cloned() {
            Some(client)
        } else {
            error!("`FederationManager.scid_to_federation` is out of sync with `FederationManager.clients`! This is a bug.");
            None
        }
    }

    pub async fn get_scid_for_federation(&self, federation_id: FederationId) -> Option<u64> {
        self.scid_to_federation
            .read()
            .await
            .iter()
            .find_map(|(scid, fid)| {
                if *fid == federation_id {
                    Some(*scid)
                } else {
                    None
                }
            })
    }

    pub async fn clone_scid_map(&self) -> BTreeMap<u64, FederationId> {
        self.scid_to_federation.read().await.clone()
    }

    pub async fn has_federation(&self, federation_id: FederationId) -> bool {
        self.clients.read().await.contains_key(&federation_id)
    }
}
