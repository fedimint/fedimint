use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use async_trait::async_trait;
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ModuleConfigResponse, ServerModuleConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::db::{Database, DatabaseVersion, MigrationMap, ModuleDatabaseTransaction};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ConsensusProposal, CoreConsensusVersion, ExtendsCommonModuleGen,
    InputMeta, ModuleConsensusVersion, ModuleError, PeerHandle, ServerModuleGen,
    SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::{OutPoint, PeerId, ServerModule};
use fedimint_dummy_common::config::{DummyConfig, DummyConfigConsensus, DummyConfigPrivate};
use fedimint_dummy_common::db::migrate_dummy_db_version_0;
use fedimint_dummy_common::{
    DummyCommonGen, DummyConsensusItem, DummyInput, DummyModuleTypes, DummyOutput,
    DummyOutputOutcome,
};
use futures::FutureExt;

#[derive(Debug, Clone)]
pub struct DummyServerGen;

impl ExtendsCommonModuleGen for DummyServerGen {
    type Common = DummyCommonGen;
}

#[async_trait]
impl ServerModuleGen for DummyServerGen {
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion(0)]
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        _env: &BTreeMap<OsString, OsString>,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Dummy::new(cfg.to_typed()?).into())
    }

    fn get_database_migrations(&self) -> MigrationMap {
        let mut migrations = MigrationMap::new();

        migrations.insert(DatabaseVersion(0), move |dbtx| {
            migrate_dummy_db_version_0(dbtx).boxed()
        });

        migrations
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let mint_cfg: BTreeMap<_, DummyConfig> = peers
            .iter()
            .map(|&peer| {
                let config = DummyConfig {
                    private: DummyConfigPrivate {
                        something_private: 3,
                    },
                    consensus: DummyConfigConsensus { something: 1 },
                };
                (peer, config)
            })
            .collect();

        mint_cfg
            .into_iter()
            .map(|(k, v)| (k, v.to_erased()))
            .collect()
    }

    async fn distributed_gen(
        &self,
        _peers: &PeerHandle,
        _params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let server = DummyConfig {
            private: DummyConfigPrivate {
                something_private: 3,
            },
            consensus: DummyConfigConsensus { something: 2 },
        };

        Ok(server.to_erased())
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        let config = serde_json::from_value::<DummyConfigConsensus>(config)?;

        Ok(ModuleConfigResponse {
            client: config.to_client_config(),
            consensus_hash: config.consensus_hash()?,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config.to_typed::<DummyConfig>()?.validate_config(identity)
    }

    async fn dump_database(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

/// Dummy module
#[derive(Debug)]
pub struct Dummy {
    pub cfg: DummyConfig,
}

#[async_trait]
impl ServerModule for Dummy {
    type Common = DummyModuleTypes;
    type Gen = DummyServerGen;
    type VerificationCache = DummyVerificationCache;

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(0, 0, &[(0, 0)])
    }

    async fn await_consensus_proposal(&self, _dbtx: &mut ModuleDatabaseTransaction<'_>) {
        std::future::pending().await
    }

    async fn consensus_proposal(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ConsensusProposal<DummyConsensusItem> {
        ConsensusProposal::empty()
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
        _consensus_items: Vec<(PeerId, DummyConsensusItem)>,
        _consensus_peers: &BTreeSet<PeerId>,
    ) -> Vec<PeerId> {
        vec![]
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a DummyInput> + Send,
    ) -> Self::VerificationCache {
        DummyVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        _input: &'a DummyInput,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        _interconnect: &'a dyn ModuleInterconect,
        _dbtx: &mut ModuleDatabaseTransaction<'c>,
        _input: &'b DummyInput,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn validate_output(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _output: &DummyOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
        _output: &'a DummyOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        _consensus_peers: &BTreeSet<PeerId>,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        vec![]
    }

    async fn output_status(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<DummyOutputOutcome> {
        None
    }

    async fn audit(&self, _dbtx: &mut ModuleDatabaseTransaction<'_>, _audit: &mut Audit) {}

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            "dummy",
            async |_module: &Dummy, _dbtx, _request: ()| -> () {
                Ok(())
            }
        }]
    }
}

#[derive(Debug, Clone)]
pub struct DummyVerificationCache;

impl fedimint_core::server::VerificationCache for DummyVerificationCache {}

impl Dummy {
    /// Create new module instance
    pub fn new(cfg: DummyConfig) -> Dummy {
        Dummy { cfg }
    }
}
