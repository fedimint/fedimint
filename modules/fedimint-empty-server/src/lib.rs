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
use fedimint_core::db::{CoreMigrationFn, DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, PeerHandle, SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::{InPoint, OutPoint, PeerId, push_db_pair_items};
use fedimint_empty_common::config::{
    EmptyClientConfig, EmptyConfig, EmptyConfigConsensus, EmptyConfigLocal, EmptyConfigPrivate,
    EmptyGenParams,
};
use fedimint_empty_common::{
    EmptyCommonInit, EmptyConsensusItem, EmptyInput, EmptyInputError, EmptyModuleTypes,
    EmptyOutput, EmptyOutputError, EmptyOutputOutcome, MODULE_CONSENSUS_VERSION,
};
use fedimint_server_core::{DynServerModule, ServerModule, ServerModuleInit, ServerModuleInitArgs};
use futures::StreamExt;
use strum::IntoEnumIterator;

use crate::db::{DbKeyPrefix, EmptyExampleKeyPrefix};

pub mod db;

/// Generates the module
#[derive(Debug, Clone)]
pub struct EmptyInit;

// TODO: Boilerplate-code
impl ModuleInit for EmptyInit {
    type Common = EmptyCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        // TODO: Boilerplate-code
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Example => {
                    push_db_pair_items!(
                        dbtx,
                        EmptyExampleKeyPrefix,
                        EmptyExampleKey,
                        Vec<u8>,
                        items,
                        "Empty Example"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for EmptyInit {
    type Module = Empty;
    type Params = EmptyGenParams;

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
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Empty::new(args.cfg().to_typed()?).into())
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
                let config = EmptyConfig {
                    local: EmptyConfigLocal {},
                    private: EmptyConfigPrivate,
                    consensus: EmptyConfigConsensus {},
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> anyhow::Result<ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();

        Ok(EmptyConfig {
            local: EmptyConfigLocal {},
            private: EmptyConfigPrivate,
            consensus: EmptyConfigConsensus {},
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<EmptyClientConfig> {
        let _config = EmptyConfigConsensus::from_erased(config)?;
        Ok(EmptyClientConfig {})
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
        BTreeMap::new()
    }
}

/// Empty module
#[derive(Debug)]
pub struct Empty {
    pub cfg: EmptyConfig,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Empty {
    /// Define the consensus types
    type Common = EmptyModuleTypes;
    type Init = EmptyInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<EmptyConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: EmptyConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // WARNING: `process_consensus_item` should return an `Err` for items that do
        // not change any internal consensus state. Failure to do so, will result in an
        // (potentially significantly) increased consensus history size.
        // If you are using this code as a template,
        // make sure to read the [`ServerModule::process_consensus_item`] documentation,
        bail!("The empty module does not use consensus items");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b EmptyInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, EmptyInputError> {
        Err(EmptyInputError::NotSupported)
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a EmptyOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, EmptyOutputError> {
        Err(EmptyOutputError::NotSupported)
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<EmptyOutputOutcome> {
        None
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

impl Empty {
    /// Create new module instance
    pub fn new(cfg: EmptyConfig) -> Empty {
        Empty { cfg }
    }
}
