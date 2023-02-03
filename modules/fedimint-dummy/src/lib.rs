use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fmt;

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use common::DummyDecoder;
use fedimint_api::cancellable::Cancellable;
use fedimint_api::config::{
    ConfigGenParams, DkgPeerMsg, ModuleGenParams, ServerModuleConfig, TypedServerModuleConfig,
};
use fedimint_api::config::{ModuleConfigResponse, TypedServerModuleConsensusConfig};
use fedimint_api::core::{ModuleInstanceId, ModuleKind};
use fedimint_api::db::{Database, DatabaseTransaction};
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::__reexports::serde_json;
use fedimint_api::module::audit::Audit;
use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::{
    api_endpoint, ApiEndpoint, InputMeta, ModuleError, ModuleGen, TransactionItemAmount,
};
use fedimint_api::net::peers::MuxPeerConnections;
use fedimint_api::server::DynServerModule;
use fedimint_api::task::TaskGroup;
use fedimint_api::{plugin_types_trait_impl, OutPoint, PeerId, ServerModule};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{DummyClientConfig, DummyConfig, DummyConfigConsensus, DummyConfigPrivate};
use crate::serde_json::Value;

pub mod common;
pub mod config;
pub mod db;

const KIND: ModuleKind = ModuleKind::from_static_str("dummy");

/// Dummy module
#[derive(Debug)]
pub struct Dummy {
    pub cfg: DummyConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DummyOutputConfirmation;

#[derive(Debug, Clone)]
pub struct DummyVerificationCache;

#[derive(Debug)]
pub struct DummyConfigGenerator;

#[async_trait]
impl ModuleGen for DummyConfigGenerator {
    const KIND: ModuleKind = KIND;
    type Decoder = DummyDecoder;

    fn decoder(&self) -> DummyDecoder {
        DummyDecoder
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

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let _params = params
            .get::<DummyConfigGenParams>()
            .expect("Invalid mint params");

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
        params: &ConfigGenParams,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<Cancellable<ServerModuleConfig>> {
        let _params = params
            .get::<DummyConfigGenParams>()
            .expect("Invalid mint params");

        let server = DummyConfig {
            private: DummyConfigPrivate {
                something_private: 3,
            },
            consensus: DummyConfigConsensus { something: 2 },
        };

        Ok(Ok(server.to_erased()))
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

impl fmt::Display for DummyOutputConfirmation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputConfirmation")
    }
}

#[async_trait]
impl ServerModule for Dummy {
    type Gen = DummyConfigGenerator;
    type Decoder = DummyDecoder;
    type Input = DummyInput;
    type Output = DummyOutput;
    type OutputOutcome = DummyOutputOutcome;
    type ConsensusItem = DummyOutputConfirmation;
    type VerificationCache = DummyVerificationCache;

    fn decoder(&self) -> Self::Decoder {
        DummyDecoder
    }

    async fn await_consensus_proposal(&self, _dbtx: &mut DatabaseTransaction<'_>) {
        std::future::pending().await
    }

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<Self::ConsensusItem> {
        vec![]
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
    ) {
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a Self::Input> + Send,
    ) -> Self::VerificationCache {
        DummyVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        _dbtx: &mut DatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        _input: &'a Self::Input,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        _interconnect: &'a dyn ModuleInterconect,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b Self::Input,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn validate_output(
        &self,
        _dbtx: &mut DatabaseTransaction,
        _output: &Self::Output,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a Self::Output,
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
    ) -> Option<Self::OutputOutcome> {
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

// Must be unique.
// TODO: we need to provide guidence for allocating these
pub const MODULE_KEY_DUMMY: u16 = 128;
plugin_types_trait_impl!(
    MODULE_KEY_DUMMY,
    DummyInput,
    DummyOutput,
    DummyOutputOutcome,
    DummyOutputConfirmation,
    DummyVerificationCache
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum DummyError {
    #[error("Something went wrong")]
    SomethingDummyWentWrong,
}
