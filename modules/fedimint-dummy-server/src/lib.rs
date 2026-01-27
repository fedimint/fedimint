#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;

use anyhow::bail;
use async_trait::async_trait;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
};
use fedimint_core::{Amount, InPoint, OutPoint, PeerId};
pub use fedimint_dummy_common as common;
use fedimint_dummy_common::config::{
    DummyClientConfig, DummyConfig, DummyConfigConsensus, DummyConfigPrivate,
};
use fedimint_dummy_common::{
    DummyCommonInit, DummyConsensusItem, DummyInput, DummyInputError, DummyModuleTypes,
    DummyOutput, DummyOutputError, DummyOutputOutcome, MODULE_CONSENSUS_VERSION,
};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};

use crate::db::{DummyAssetsKey, DummyAssetsPrefix};

pub mod db;

/// Generates the module
#[derive(Debug, Clone)]
pub struct DummyInit;

impl ModuleInit for DummyInit {
    type Common = DummyCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();

        if (prefix_names.is_empty() || prefix_names.contains(&"assets".to_string()))
            && let Some(assets) = dbtx.get_value(&DummyAssetsKey).await
        {
            items.insert("Dummy Assets".to_string(), Box::new(assets));
        }

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for DummyInit {
    type Module = Dummy;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    /// Initialize the module
    async fn init(&self, _args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Dummy)
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        peers
            .iter()
            .map(|&peer| {
                let config = DummyConfig {
                    private: DummyConfigPrivate,
                    consensus: DummyConfigConsensus,
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        _args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        Ok(DummyConfig {
            private: DummyConfigPrivate,
            consensus: DummyConfigConsensus,
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        _config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<DummyClientConfig> {
        Ok(DummyClientConfig)
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Dummy>> {
        BTreeMap::new()
    }
}

/// Dummy module
#[derive(Debug)]
pub struct Dummy;

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Dummy {
    /// Define the consensus types
    type Common = DummyModuleTypes;
    type Init = DummyInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<DummyConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: DummyConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        bail!("The dummy module does not use consensus items");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b DummyInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, DummyInputError> {
        // Add to federation assets (user is depositing value)
        let current_assets = dbtx
            .get_value(&DummyAssetsKey)
            .await
            .unwrap_or(Amount::ZERO);
        let updated_assets = current_assets + input.amount;
        dbtx.insert_entry(&DummyAssetsKey, &updated_assets).await;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(input.amount),
                fees: Amounts::ZERO,
            },
            pub_key: input.key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a DummyOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, DummyOutputError> {
        // Subtract from federation assets (federation is paying out value)
        let current_assets = dbtx
            .get_value(&DummyAssetsKey)
            .await
            .unwrap_or(Amount::ZERO);
        let updated_assets = current_assets.saturating_sub(output.amount);
        dbtx.insert_entry(&DummyAssetsKey, &updated_assets).await;

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin(output.amount),
            fees: Amounts::ZERO,
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<DummyOutputOutcome> {
        // Dummy module doesn't track output outcomes
        None
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        // The assets value represents how much the federation has received via inputs
        // minus how much it has paid out via outputs. A positive value means
        // assets > liabilities.
        audit
            .add_items(dbtx, module_instance_id, &DummyAssetsPrefix, |_k, v| {
                v.msats as i64
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        Vec::new()
    }
}
