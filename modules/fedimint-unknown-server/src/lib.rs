#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;

use anyhow::bail;
use async_trait::async_trait;
use fedimint_core::config::{
    ConfigGenModuleParams, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::{InPoint, OutPoint, PeerId};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{ServerModule, ServerModuleInit, ServerModuleInitArgs};
pub use fedimint_unknown_common as common;
use fedimint_unknown_common::config::{
    UnknownClientConfig, UnknownConfig, UnknownConfigConsensus, UnknownConfigLocal,
    UnknownConfigPrivate, UnknownGenParams,
};
use fedimint_unknown_common::{
    MODULE_CONSENSUS_VERSION, UnknownCommonInit, UnknownConsensusItem, UnknownInput,
    UnknownInputError, UnknownModuleTypes, UnknownOutput, UnknownOutputError, UnknownOutputOutcome,
};
pub mod db;

/// Generates the module
#[derive(Debug, Clone)]
pub struct UnknownInit;

// TODO: Boilerplate-code
impl ModuleInit for UnknownInit {
    type Common = UnknownCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(vec![].into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for UnknownInit {
    type Module = Unknown;
    type Params = UnknownGenParams;

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
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Unknown::new(args.cfg().to_typed()?))
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let config = UnknownConfig {
                    local: UnknownConfigLocal {},
                    private: UnknownConfigPrivate,
                    consensus: UnknownConfigConsensus {},
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        params: &ConfigGenModuleParams,
    ) -> anyhow::Result<ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();

        Ok(UnknownConfig {
            local: UnknownConfigLocal {},
            private: UnknownConfigPrivate,
            consensus: UnknownConfigConsensus {},
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<UnknownClientConfig> {
        let _config = UnknownConfigConsensus::from_erased(config)?;
        Ok(UnknownClientConfig {})
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
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Unknown>> {
        let mut migrations: BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<_>> =
            BTreeMap::new();
        // Unknown module prior to v0.5.0 had a `DATABASE_VERSION` of 1, so we must
        // insert a no-op migration to ensure that upgrades work.
        migrations.insert(DatabaseVersion(0), Box::new(|_| Box::pin(async { Ok(()) })));
        migrations
    }
}

/// Unknown module
#[derive(Debug)]
pub struct Unknown {
    pub cfg: UnknownConfig,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Unknown {
    /// Define the consensus types
    type Common = UnknownModuleTypes;
    type Init = UnknownInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<UnknownConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: UnknownConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // WARNING: `process_consensus_item` should return an `Err` for items that do
        // not change any internal consensus state. Failure to do so, will result in an
        // (potentially significantly) increased consensus history size.
        // If you are using this code as a template,
        // make sure to read the [`ServerModule::process_consensus_item`] documentation,
        bail!("The unknown module does not use consensus items");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b UnknownInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, UnknownInputError> {
        unreachable!();
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a UnknownOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, UnknownOutputError> {
        unreachable!();
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<UnknownOutputOutcome> {
        unreachable!()
    }

    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        Vec::new()
    }
}

impl Unknown {
    /// Create new module instance
    pub fn new(cfg: UnknownConfig) -> Unknown {
        Unknown { cfg }
    }
}
