use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result};
use fedimint_connectors::PeerStatus;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::{CommonModuleInit, ModuleConsensusVersion};
use fedimint_core::util::Spanned;
use fedimint_core::{NumPeers, PeerId};
use fedimint_gateway_common::{
    FederationConnectivity, FederationStatusResponse, LightningMode, LightningModuleStatus,
    Lnv1RegistrationStatus, Lnv2RegistrationStatus,
};
use fedimint_gateway_server_db::GatewayDbtxNcExt as _;
use fedimint_gw_client::GatewayClientModule;
use fedimint_gwv2_client::GatewayClientModuleV2;
use fedimint_ln_common::LightningCommonInit;
use fedimint_lnv2_common::LightningCommonInit as LightningV2CommonInit;
use futures::StreamExt as _;
use lightning_invoice::RoutingFees;

use crate::{GW_ANNOUNCEMENT_TTL, Gateway};

fn federation_connectivity(
    connection_status: &BTreeMap<PeerId, PeerStatus>,
) -> FederationConnectivity {
    let connected = connection_status
        .values()
        .filter(|status| matches!(status, PeerStatus::Connected(_)))
        .count();
    if connected == 0 {
        FederationConnectivity::Disconnected
    } else if connected < NumPeers::from(connection_status.len()).threshold() {
        FederationConnectivity::Degraded
    } else {
        FederationConnectivity::Connected
    }
}

struct LightningModuleSnapshot<R> {
    /// Configured instances of this module generation.
    configured: Vec<(ModuleInstanceId, ModuleConsensusVersion)>,
    /// Configured instances that the client initialized.
    initialized: BTreeSet<ModuleInstanceId>,
    /// Exact operational instance.
    operational: Option<ModuleInstanceId>,
    /// Discovery ownership and retained registration facts.
    registration: R,
}

impl<R> LightningModuleSnapshot<R> {
    /// Converts a coherent module snapshot into its public status.
    fn into_status(self) -> Result<LightningModuleStatus<R>> {
        if let Some((uninitialized_id, _)) = self
            .configured
            .iter()
            .find(|(id, _)| !self.initialized.contains(id))
        {
            anyhow::bail!("configured Lightning module {uninitialized_id} was not initialized");
        }
        let Some(operational_id) = self.operational else {
            return if self.configured.is_empty() {
                Ok(LightningModuleStatus::Absent {})
            } else {
                anyhow::bail!("configured Lightning module was not initialized")
            };
        };
        let (_, consensus_version) = self
            .configured
            .iter()
            .find(|(configured_id, _)| *configured_id == operational_id)
            .context("initialized Lightning module is absent from the federation config")?;
        Ok(LightningModuleStatus::Supported {
            consensus_version: *consensus_version,
            registration: self.registration,
        })
    }
}

struct FederationStatusSnapshot {
    /// Requested federation.
    federation_id: FederationId,
    /// Aggregated live connection state.
    connectivity: FederationConnectivity,
    /// LNv1 module snapshot.
    lnv1: LightningModuleSnapshot<Lnv1RegistrationStatus>,
    /// LNv2 module snapshot.
    lnv2: LightningModuleSnapshot<Lnv2RegistrationStatus>,
}

impl FederationStatusSnapshot {
    /// Assembles the complete served response from one bounded snapshot.
    fn into_response(self) -> Result<FederationStatusResponse> {
        Ok(FederationStatusResponse::served(
            self.federation_id,
            self.connectivity,
            self.lnv1
                .into_status()
                .context("LNv1 status invariant failed")?,
            self.lnv2
                .into_status()
                .context("LNv2 status invariant failed")?,
        ))
    }
}

impl Gateway {
    /// Returns public capability and health data scoped to one requested
    /// federation.
    pub async fn handle_federation_status(
        &self,
        federation_id: FederationId,
    ) -> Result<FederationStatusResponse> {
        // Keep the manager read guard until the snapshot is complete. This avoids
        // cloning the client Arc, which would make concurrent admin leave fail its
        // exclusive-ownership check; Tokio's writer-preferring lock prevents a
        // stream of public readers from starving leave.
        let federation_manager = self.federation_manager.read().await;
        let Some(client) = federation_manager
            .client(&federation_id)
            .map(Spanned::value)
        else {
            return Ok(FederationStatusResponse::unserved(federation_id));
        };

        let connection_status = client
            .connection_status_stream()
            .next()
            .await
            .unwrap_or_default();
        let connectivity = federation_connectivity(&connection_status);

        let config = client.config().await;
        let lnv1_operational_id = client
            .get_first_module::<GatewayClientModule>()
            .ok()
            .map(|module| module.id);
        let lnv2_operational_id = client
            .get_first_module::<GatewayClientModuleV2>()
            .ok()
            .map(|module| module.id);
        let lnv1_configured_modules = config
            .modules
            .iter()
            .filter(|(_, module)| module.kind == LightningCommonInit::KIND)
            .map(|(id, module)| (*id, module.version))
            .collect();
        let lnv2_configured_modules = config
            .modules
            .iter()
            .filter(|(_, module)| module.kind == LightningV2CommonInit::KIND)
            .map(|(id, module)| (*id, module.version))
            .collect();
        let initialized_modules = config
            .modules
            .keys()
            .filter(|id| client.has_module(**id))
            .copied()
            .collect::<BTreeSet<_>>();

        let lnv1_registration_configured = matches!(self.lightning_mode, LightningMode::Lnd { .. })
            && !self.registrations.is_empty()
            && self
                .gateway_db
                .begin_transaction_nc()
                .await
                .load_federation_config(federation_id)
                .await
                .is_some_and(|config| RoutingFees::try_from(config.lightning_fee).is_ok());
        let lnv1_endpoints = self
            .registration_health
            .lnv1_status(
                federation_id,
                self.registrations.keys().cloned(),
                GW_ANNOUNCEMENT_TTL,
                fedimint_core::runtime::Instant::now(),
            )
            .await;
        FederationStatusSnapshot {
            federation_id,
            connectivity,
            lnv1: LightningModuleSnapshot {
                configured: lnv1_configured_modules,
                initialized: initialized_modules.clone(),
                operational: lnv1_operational_id,
                registration: Lnv1RegistrationStatus::GatewayManaged {
                    configured: lnv1_registration_configured,
                    endpoints: lnv1_endpoints,
                },
            },
            lnv2: LightningModuleSnapshot {
                configured: lnv2_configured_modules,
                initialized: initialized_modules,
                operational: lnv2_operational_id,
                registration: Lnv2RegistrationStatus::FederationManaged,
            },
        }
        .into_response()
    }
}

#[cfg(test)]
mod tests;
