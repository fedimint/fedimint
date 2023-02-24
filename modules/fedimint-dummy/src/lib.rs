use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fmt;

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::config::{
    ConfigGenParams, DkgPeerMsg, DkgResult, ModuleConfigResponse, ModuleGenParams,
    ServerModuleConfig, TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion, MigrationMap};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiVersion, ConsensusProposal, CoreConsensusVersion, InputMeta,
    ModuleCommon, ModuleConsensusVersion, ModuleError, ModuleGen, TransactionItemAmount,
};
use fedimint_core::net::peers::MuxPeerConnections;
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::{plugin_types_trait_impl, OutPoint, PeerId, ServerModule};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{DummyClientConfig, DummyConfig, DummyConfigConsensus, DummyConfigPrivate};
use crate::db::migrate_dummy_db_version_0;
use crate::serde_json::Value;

pub mod config;
pub mod db;

const KIND: ModuleKind = ModuleKind::from_static_str("dummy");

/// Dummy module
#[derive(Debug)]
pub struct Dummy {
    pub cfg: DummyConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DummyConsensusItem;

#[derive(Debug, Clone)]
pub struct DummyVerificationCache;

#[derive(Debug)]
pub struct DummyConfigGenerator;

#[async_trait]
impl ModuleGen for DummyConfigGenerator {
    const KIND: ModuleKind = KIND;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    fn decoder(&self) -> Decoder {
        <Dummy as ServerModule>::decoder()
    }

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
        _params: &ConfigGenParams,
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
        _connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        _our_id: &PeerId,
        _instance_id: ModuleInstanceId,
        _peers: &[PeerId],
        _params: &ConfigGenParams,
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

    fn hash_client_module(&self, config: Value) -> anyhow::Result<sha256::Hash> {
        serde_json::from_value::<DummyClientConfig>(config)?.consensus_hash()
    }

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyConfigGenParams {
    pub important_param: u64,
}

impl ModuleGenParams for DummyConfigGenParams {
    const MODULE_NAME: &'static str = "dummy";
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct DummyInput;

impl fmt::Display for DummyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyInput")
    }
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct DummyOutput;

impl fmt::Display for DummyOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutput")
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct DummyOutputOutcome;

impl fmt::Display for DummyOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputOutcome")
    }
}

impl fmt::Display for DummyConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputConfirmation")
    }
}

pub struct DummyModuleTypes;

impl ModuleCommon for DummyModuleTypes {
    type Input = DummyInput;
    type Output = DummyOutput;
    type OutputOutcome = DummyOutputOutcome;
    type ConsensusItem = DummyConsensusItem;
}

#[async_trait]
impl ServerModule for Dummy {
    type Common = DummyModuleTypes;
    type Gen = DummyConfigGenerator;
    type VerificationCache = DummyVerificationCache;

    fn versions(&self) -> (ModuleConsensusVersion, &[ApiVersion]) {
        (
            ModuleConsensusVersion(0),
            &[ApiVersion { major: 0, minor: 0 }],
        )
    }

    async fn await_consensus_proposal(&self, _dbtx: &mut DatabaseTransaction<'_>) {
        std::future::pending().await
    }

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> ConsensusProposal<DummyConsensusItem> {
        ConsensusProposal::empty()
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_items: Vec<(PeerId, DummyConsensusItem)>,
    ) {
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
        _dbtx: &mut DatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        _input: &'a DummyInput,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        _interconnect: &'a dyn ModuleInterconect,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b DummyInput,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn validate_output(
        &self,
        _dbtx: &mut DatabaseTransaction,
        _output: &DummyOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a DummyOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        _consensus_peers: &HashSet<PeerId>,
        _dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        vec![]
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<DummyOutputOutcome> {
        None
    }

    async fn audit(&self, _dbtx: &mut DatabaseTransaction<'_>, _audit: &mut Audit) {}

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            "/dummy",
            async |_module: &Dummy, _dbtx, _request: ()| -> () {
                Ok(())
            }
        }]
    }
}

impl Dummy {
    /// Create new module instance
    pub fn new(cfg: DummyConfig) -> Dummy {
        Dummy { cfg }
    }
}

plugin_types_trait_impl!(
    DummyInput,
    DummyOutput,
    DummyOutputOutcome,
    DummyConsensusItem,
    DummyVerificationCache
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum DummyError {
    #[error("Something went wrong")]
    SomethingDummyWentWrong,
}
