use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bitcoin::secp256k1::Keypair;
use fedimint_client::ClientHandleArc;
use fedimint_core::config::{FederationId, FederationIdPrefix, JsonClientConfig};
use fedimint_core::db::{DatabaseTransaction, NonCommittable};
use fedimint_core::util::Spanned;
use tracing::info;

use crate::db::GatewayDbtxNcExt;
use crate::error::{AdminGatewayError, FederationNotConnected};
use crate::gateway_module_v2::GatewayClientModuleV2;
use crate::rpc::FederationInfo;
use crate::state_machine::GatewayClientModule;
use crate::AdminResult;

/// The first index that the gateway will assign to a federation.
/// Note: This starts at 1 because LNv1 uses the `federation_index` as an SCID.
/// An SCID of 0 is considered invalid by LND's HTLC interceptor.
const INITIAL_INDEX: u64 = 1;

// TODO: Add support for client lookup by payment hash (for LNv2).
#[derive(Debug)]
pub struct FederationManager {
    /// Map of `FederationId` -> `Client`. Used for efficient retrieval of the
    /// client while handling incoming HTLCs.
    clients: BTreeMap<FederationId, Spanned<fedimint_client::ClientHandleArc>>,

    /// Map of federation indices to `FederationId`. Use for efficient retrieval
    /// of the client while handling incoming HTLCs.
    /// Can be removed after LNv1 removal.
    index_to_federation: BTreeMap<u64, FederationId>,

    /// Tracker for federation index assignments. When connecting a new
    /// federation, this value is incremented and assigned to the federation
    /// as the `federation_index`
    next_index: AtomicU64,
}

impl FederationManager {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::new(),
            index_to_federation: BTreeMap::new(),
            next_index: AtomicU64::new(INITIAL_INDEX),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    pub fn add_client(&mut self, index: u64, client: Spanned<fedimint_client::ClientHandleArc>) {
        let federation_id = client.borrow().with_sync(|c| c.federation_id());
        self.clients.insert(federation_id, client);
        self.index_to_federation.insert(index, federation_id);
    }

    pub async fn leave_federation(
        &mut self,
        federation_id: FederationId,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
    ) -> AdminResult<FederationInfo> {
        let federation_info = self.federation_info(federation_id, dbtx).await?;

        let gateway_keypair = dbtx.load_gateway_keypair_assert_exists().await;

        self.unannounce_from_federation(federation_id, gateway_keypair)
            .await?;

        self.remove_client(federation_id).await?;

        Ok(federation_info)
    }

    async fn remove_client(&mut self, federation_id: FederationId) -> AdminResult<()> {
        let client = self
            .clients
            .remove(&federation_id)
            .ok_or(FederationNotConnected {
                federation_id_prefix: federation_id.to_prefix(),
            })?
            .into_value();

        self.index_to_federation
            .retain(|_, fid| *fid != federation_id);

        if let Some(client) = Arc::into_inner(client) {
            client.shutdown().await;
            Ok(())
        } else {
            Err(AdminGatewayError::ClientRemovalError(format!(
                "Federation client {federation_id} is not unique, failed to shutdown client"
            )))
        }
    }

    /// Waits for ongoing incoming LNv1 and LNv2 payments to complete before
    /// returning.
    pub async fn wait_for_incoming_payments(&self) -> AdminResult<()> {
        for client in self.clients.values() {
            let active_operations = client.value().get_active_operations().await;
            let operation_log = client.value().operation_log();
            for op_id in active_operations {
                let log_entry = operation_log.get_operation(op_id).await;
                if let Some(entry) = log_entry {
                    match entry.operation_module_kind() {
                        "lnv2" => {
                            let lnv2 =
                                client.value().get_first_module::<GatewayClientModuleV2>()?;
                            lnv2.await_completion(op_id).await;
                        }
                        "ln" => {
                            let lnv1 = client.value().get_first_module::<GatewayClientModule>()?;
                            lnv1.await_completion(op_id).await;
                        }
                        _ => continue,
                    }
                }
            }
        }

        info!("Finished waiting for incoming payments");
        Ok(())
    }

    async fn unannounce_from_federation(
        &self,
        federation_id: FederationId,
        gateway_keypair: Keypair,
    ) -> AdminResult<()> {
        let client = self
            .clients
            .get(&federation_id)
            .ok_or(FederationNotConnected {
                federation_id_prefix: federation_id.to_prefix(),
            })?;

        client
            .value()
            .get_first_module::<GatewayClientModule>()?
            .remove_from_federation(gateway_keypair)
            .await;

        Ok(())
    }

    /// Iterates through all of the federations the gateway is registered with
    /// and requests to remove the registration record.
    pub async fn unannounce_from_all_federations(&self, gateway_keypair: Keypair) {
        let removal_futures = self
            .clients
            .values()
            .map(|client| async {
                client
                    .value()
                    .get_first_module::<GatewayClientModule>()
                    .expect("Must have client module")
                    .remove_from_federation(gateway_keypair)
                    .await;
            })
            .collect::<Vec<_>>();

        futures::future::join_all(removal_futures).await;
    }

    pub fn get_client_for_index(&self, short_channel_id: u64) -> Option<Spanned<ClientHandleArc>> {
        let federation_id = self.index_to_federation.get(&short_channel_id)?;
        // TODO(tvolk131): Cloning the client here could cause issues with client
        // shutdown (see `remove_client` above). Perhaps this function should take a
        // lambda and pass it into `client.with_sync`.
        if let Some(client) = self.clients.get(federation_id).cloned() {
            Some(client)
        } else {
            panic!("`FederationManager.index_to_federation` is out of sync with `FederationManager.clients`! This is a bug.");
        }
    }

    fn get_index_for_federation(&self, federation_id: FederationId) -> Option<u64> {
        self.index_to_federation.iter().find_map(|(index, fid)| {
            if *fid == federation_id {
                Some(*index)
            } else {
                None
            }
        })
    }

    pub fn get_client_for_federation_id_prefix(
        &self,
        federation_id_prefix: FederationIdPrefix,
    ) -> Option<Spanned<ClientHandleArc>> {
        self.clients.iter().find_map(|(fid, client)| {
            if fid.to_prefix() == federation_id_prefix {
                Some(client.clone())
            } else {
                None
            }
        })
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
    ) -> std::result::Result<FederationInfo, FederationNotConnected> {
        let Some(federation_index) = self.get_index_for_federation(federation_id) else {
            return Err(FederationNotConnected {
                federation_id_prefix: federation_id.to_prefix(),
            });
        };

        self.clients
            .get(&federation_id)
            .expect("`FederationManager.index_to_federation` is out of sync with `FederationManager.clients`! This is a bug.")
            .borrow()
            .with(|client| async move {
                let balance_msat = client.get_balance().await;

                let routing_fees = dbtx
                    .load_federation_config(federation_id)
                    .await
                    .map(|config| config.fees.into());

                Ok(FederationInfo {
                    federation_id,
                    federation_name: self.federation_name(client).await,
                    balance_msat,
                    federation_index,
                    routing_fees,
                })
            })
            .await
    }

    pub async fn federation_name(&self, client: &ClientHandleArc) -> Option<String> {
        let client_config = client.config().await;
        let federation_name = client_config.global.federation_name();
        federation_name.map(String::from)
    }

    pub async fn federation_info_all_federations(
        &self,
        mut dbtx: DatabaseTransaction<'_, NonCommittable>,
    ) -> Vec<FederationInfo> {
        let mut federation_infos = Vec::new();
        for (federation_id, client) in &self.clients {
            let federation_index = self.get_index_for_federation(*federation_id).expect("`FederationManager.index_to_federation` is out of sync with `FederationManager.clients`! This is a bug.");

            let balance_msat = client.borrow().with(|client| client.get_balance()).await;

            let routing_fees = dbtx
                .load_federation_config(*federation_id)
                .await
                .map(|config| config.fees.into());

            federation_infos.push(FederationInfo {
                federation_id: *federation_id,
                federation_name: self.federation_name(client.value()).await,
                balance_msat,
                federation_index,
                routing_fees,
            });
        }
        federation_infos
    }

    pub async fn get_federation_config(
        &self,
        federation_id: FederationId,
    ) -> AdminResult<JsonClientConfig> {
        let client = self
            .clients
            .get(&federation_id)
            .ok_or(FederationNotConnected {
                federation_id_prefix: federation_id.to_prefix(),
            })?;
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
    pub fn set_next_index(&self, next_index: u64) {
        self.next_index.store(next_index, Ordering::SeqCst);
    }

    pub fn pop_next_index(&self) -> AdminResult<u64> {
        let next_index = self.next_index.fetch_add(1, Ordering::Relaxed);

        // Check for overflow.
        if next_index == INITIAL_INDEX.wrapping_sub(1) {
            return Err(AdminGatewayError::GatewayConfigurationError(
                "Federation Index overflow".to_string(),
            ));
        }

        Ok(next_index)
    }
}
