use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bitcoin::secp256k1::KeyPair;
use fedimint_client::ClientHandleArc;
use fedimint_core::config::FederationId;
use fedimint_core::util::Spanned;
use tracing::error;

use crate::state_machine::GatewayClientModule;
use crate::{GatewayError, Result};

/// The first SCID that the gateway will assign to a federation.
/// Note: This starts at 1 because an SCID of 0 is considered invalid by LND's
/// HTLC interceptor.
const INITIAL_SCID: u64 = 1;

#[derive(Debug)]
pub struct FederationManager {
    /// Map of `FederationId` -> `Client`. Used for efficient retrieval of the
    /// client while handling incoming HTLCs.
    clients: BTreeMap<FederationId, Spanned<fedimint_client::ClientHandleArc>>,

    /// Map of short channel ids to `FederationId`. Use for efficient retrieval
    /// of the client while handling incoming HTLCs.
    scid_to_federation: BTreeMap<u64, FederationId>,

    /// Tracker for short channel ID assignments. When connecting a new
    /// federation, this value is incremented and assigned to the federation
    /// as the `mint_channel_id`
    next_scid: AtomicU64,
}

impl FederationManager {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::new(),
            scid_to_federation: BTreeMap::new(),
            next_scid: AtomicU64::new(INITIAL_SCID),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    pub fn add_client(
        &mut self,
        scid: u64,
        federation_id: FederationId,
        client: Spanned<fedimint_client::ClientHandleArc>,
    ) {
        self.clients.insert(federation_id, client);
        self.scid_to_federation.insert(scid, federation_id);
    }

    pub async fn remove_client(&mut self, federation_id: FederationId) -> Result<()> {
        let client = self
            .clients
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
            .retain(|_, fid| *fid != federation_id);
        Ok(())
    }

    /// Iterates through all of the federations the gateway is registered with
    /// and requests to remove the registration record.
    pub async fn leave_all_federations(&self, gateway_keypair: KeyPair) {
        let removal_futures = self
            .clients
            .values()
            .map(|client| async {
                client
                    .value()
                    .get_first_module::<GatewayClientModule>()
                    .remove_from_federation(gateway_keypair)
                    .await;
            })
            .collect::<Vec<_>>();

        futures::future::join_all(removal_futures).await;
    }

    pub fn get_client_for_scid(&self, short_channel_id: u64) -> Option<Spanned<ClientHandleArc>> {
        let federation_id = self.scid_to_federation.get(&short_channel_id)?;
        // TODO(tvolk131): Cloning the client here could cause issues with client
        // shutdown (see `remove_client` above). Perhaps this function should take a
        // lambda and pass it into `client.with_sync`.
        if let Some(client) = self.clients.get(federation_id).cloned() {
            Some(client)
        } else {
            error!("`FederationManager.scid_to_federation` is out of sync with `FederationManager.clients`! This is a bug.");
            None
        }
    }

    pub fn get_scid_for_federation(&self, federation_id: FederationId) -> Option<u64> {
        self.scid_to_federation.iter().find_map(|(scid, fid)| {
            if *fid == federation_id {
                Some(*scid)
            } else {
                None
            }
        })
    }

    pub fn clone_scid_map(&self) -> BTreeMap<u64, FederationId> {
        self.scid_to_federation.clone()
    }

    pub fn has_federation(&self, federation_id: FederationId) -> bool {
        self.clients.contains_key(&federation_id)
    }

    // TODO(tvolk131): Replace this function with more granular accessors.
    pub fn borrow_clients(
        &self,
    ) -> &BTreeMap<FederationId, Spanned<fedimint_client::ClientHandleArc>> {
        &self.clients
    }

    pub fn set_next_scid(&self, next_scid: u64) {
        self.next_scid.store(next_scid, Ordering::SeqCst);
    }

    pub fn pop_next_scid(&self) -> Result<u64> {
        let next_scid = self.next_scid.fetch_add(1, Ordering::Relaxed);

        // Check for overflow.
        if next_scid == INITIAL_SCID.wrapping_sub(1) {
            return Err(GatewayError::GatewayConfigurationError(
                "Short channel ID overflow".to_string(),
            ));
        }

        Ok(next_scid)
    }
}
