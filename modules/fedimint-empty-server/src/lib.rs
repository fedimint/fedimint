use std::collections::BTreeMap;

use anyhow::bail;
use async_trait::async_trait;
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, ServerMigrationFn};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, CoreConsensusVersion, InputMeta, ModuleConsensusVersion, ModuleInit, PeerHandle,
    ServerModuleInit, ServerModuleInitArgs, SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{push_db_pair_items, OutPoint, PeerId, ServerModule};
use fedimint_empty_common::config::{
    EmptyClientConfig, EmptyConfig, EmptyConfigConsensus, EmptyConfigLocal, EmptyConfigPrivate,
    EmptyGenParams,
};
use fedimint_empty_common::{
    EmptyCommonInit, EmptyConsensusItem, EmptyInput, EmptyInputError, EmptyModuleTypes,
    EmptyOutput, EmptyOutputError, EmptyOutputOutcome, CONSENSUS_VERSION,
};
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
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

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
    type Params = EmptyGenParams;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw((u32::MAX, 0), (0, 0), &[(0, 0)])
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
    ) -> DkgResult<ServerModuleConfig> {
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
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ServerMigrationFn> {
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
        bail!("The empty module does not use consensus items");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b EmptyInput,
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
