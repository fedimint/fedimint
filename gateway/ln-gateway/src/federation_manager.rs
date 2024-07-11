use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bitcoin::secp256k1::KeyPair;
use fedimint_client::ClientHandleArc;
use fedimint_core::config::{FederationId, JsonClientConfig};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped, NonCommittable};
use fedimint_core::util::Spanned;

use crate::db::{FederationIdKey, GatewayPublicKey};
use crate::rpc::FederationInfo;
use crate::state_machine::GatewayClientModule;
use crate::{GatewayError, Result};

/// The first SCID that the gateway will assign to a federation.
/// Note: This starts at 1 because an SCID of 0 is considered invalid by LND's
/// HTLC interceptor.
const INITIAL_SCID: u64 = 1;

// TODO: Add support for client lookup by payment hash (for LNv2).
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

    pub fn add_client(&mut self, scid: u64, client: Spanned<fedimint_client::ClientHandleArc>) {
        let federation_id = client.borrow().with_sync(|c| c.federation_id());
        self.clients.insert(federation_id, client);
        self.scid_to_federation.insert(scid, federation_id);
    }

    pub async fn leave_federation(
        &mut self,
        federation_id: FederationId,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
    ) -> Result<FederationInfo> {
        let federation_info = self.federation_info(federation_id, dbtx).await?;

        let gateway_keypair = dbtx
            .get_value(&GatewayPublicKey)
            .await
            .expect("Gateway keypair does not exist");

        self.unannounce_from_federation(federation_id, gateway_keypair)
            .await?;

        self.remove_client(federation_id).await?;

        Ok(federation_info)
    }

    async fn remove_client(&mut self, federation_id: FederationId) -> Result<()> {
        let client = self
            .clients
            .remove(&federation_id)
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))?
            .into_value();

        self.scid_to_federation
            .retain(|_, fid| *fid != federation_id);

        if let Some(client) = Arc::into_inner(client) {
            client.shutdown().await;
            Ok(())
        } else {
            Err(GatewayError::UnexpectedState(
                "Federation client is not unique, failed to shutdown client".to_string(),
            ))
        }
    }

    async fn unannounce_from_federation(
        &self,
        federation_id: FederationId,
        gateway_keypair: KeyPair,
    ) -> Result<()> {
        let client = self
            .clients
            .get(&federation_id)
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))?;

        client
            .value()
            .get_first_module::<GatewayClientModule>()
            .remove_from_federation(gateway_keypair)
            .await;

        Ok(())
    }

    /// Iterates through all of the federations the gateway is registered with
    /// and requests to remove the registration record.
    pub async fn unannounce_from_all_federations(&self, gateway_keypair: KeyPair) {
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
            panic!("`FederationManager.scid_to_federation` is out of sync with `FederationManager.clients`! This is a bug.");
        }
    }

    fn get_scid_for_federation(&self, federation_id: FederationId) -> Option<u64> {
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

    pub fn client(&self, federation_id: &FederationId) -> Option<&Spanned<ClientHandleArc>> {
        self.clients.get(federation_id)
    }

    async fn federation_info(
        &self,
        federation_id: FederationId,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
    ) -> Result<FederationInfo> {
        let channel_id = self.get_scid_for_federation(federation_id);

        self.clients
            .get(&federation_id)
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))?
            .borrow()
            .with(|client| async move {
                let balance_msat = client.get_balance().await;
                let config = client.config().await;

                let federation_key = FederationIdKey { id: federation_id };
                let routing_fees = dbtx
                    .get_value(&federation_key)
                    .await
                    .map(|config| config.fees.into());

                Ok(FederationInfo {
                    federation_id,
                    balance_msat,
                    config,
                    channel_id,
                    routing_fees,
                })
            })
            .await
    }

    pub async fn federation_info_all_federations(
        &self,
        mut dbtx: DatabaseTransaction<'_, NonCommittable>,
    ) -> Vec<FederationInfo> {
        let mut federation_infos = Vec::new();
        for (federation_id, client) in &self.clients {
            let channel_id = self.get_scid_for_federation(*federation_id);

            let balance_msat = client.borrow().with(|client| client.get_balance()).await;
            let config = client.borrow().with(|client| client.config()).await;

            let federation_key = FederationIdKey { id: *federation_id };
            let routing_fees = dbtx
                .get_value(&federation_key)
                .await
                .map(|config| config.fees.into());

            federation_infos.push(FederationInfo {
                federation_id: *federation_id,
                balance_msat,
                config,
                channel_id,
                routing_fees,
            });
        }
        federation_infos
    }

    pub async fn get_federation_config(
        &self,
        federation_id: FederationId,
    ) -> Result<JsonClientConfig> {
        let client = self
            .clients
            .get(&federation_id)
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))?;
        Ok(client
            .borrow()
            .with(|client| client.get_config_json())
            .await)
    }

    pub async fn get_all_federation_configs(&self) -> BTreeMap<FederationId, JsonClientConfig> {
        let mut federations = BTreeMap::new();
        for (federation_id, client) in &self.clients {
            federations.insert(
                *federation_id,
                client
                    .borrow()
                    .with(|client| client.get_config_json())
                    .await,
            );
        }
        federations
    }

    // TODO(tvolk131): Set this value in the constructor.
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
