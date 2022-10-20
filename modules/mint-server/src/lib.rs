use std::collections::HashSet;

use async_trait::async_trait;
use fedimint_api::{
    db::DatabaseTransaction,
    encoding::{Decodable, Encodable},
    module::{audit::Audit, interconnect::ModuleInterconect},
    Amount, OutPoint, PeerId,
};
use fedimint_core_server::{
    Error, InitHandle, InputMeta, ModuleKey, PluginConsensusItem, PluginVerificationCache,
    ServerModulePlugin,
};
use fedimint_mint_common::{
    MintInput, MintModuleCommon, MintOutput, MintOutputOutcome, MintPendingOutput,
    MintSpendableOutput, MINT_MODULE_KEY,
};

#[derive(Encodable, Decodable, Clone)]
pub struct MintVerificationCache;

impl PluginVerificationCache for MintVerificationCache {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct MintConsensusItem;

impl PluginConsensusItem for MintConsensusItem {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }
}

#[derive(Default)]
pub struct MintServerModule;

impl MintServerModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait(?Send)]
impl ServerModulePlugin for MintServerModule {
    type Common = MintModuleCommon;
    type Input = MintInput;
    type Output = MintOutput;
    type PendingOutput = MintPendingOutput;
    type SpendableOutput = MintSpendableOutput;
    type OutputOutcome = MintOutputOutcome;
    type ConsensusItem = MintConsensusItem;
    type VerificationCache = MintVerificationCache;

    fn init(&self, backend: &mut dyn InitHandle) {
        // TODO: delete this dummy endpoint
        backend.register_endpoint("/mint/echo", |value, _ctx| {
            Box::pin(async move { Ok(value) })
        });
    }

    async fn await_consensus_proposal<'a>(&'a self) {
        todo!()
    }

    async fn consensus_proposal<'a>(&'a self) -> Vec<Self::ConsensusItem> {
        todo!()
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
    ) {
        todo!()
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a Self::Input> + Send,
    ) -> Self::VerificationCache {
        todo!()
    }

    fn validate_input<'a>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        _verification_cache: &Self::VerificationCache,
        _input: &'a Self::Input,
    ) -> Result<InputMeta, Error> {
        todo!()
    }

    fn apply_input<'a, 'b, 'c>(
        &'a self,
        _interconnect: &'a dyn ModuleInterconect,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b Self::Input,
        _verification_cache: &Self::VerificationCache,
    ) -> Result<InputMeta, Error> {
        todo!()
    }

    fn validate_output(&self, _output: &Self::Output) -> Result<Amount, Error> {
        todo!()
    }

    fn apply_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a Self::Output,
        _out_point: OutPoint,
    ) -> Result<Amount, Error> {
        todo!()
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        _consensus_peers: &HashSet<PeerId>,
        _dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        todo!()
    }

    fn output_status(&self, _out_point: OutPoint) -> Option<Self::OutputOutcome> {
        todo!()
    }

    fn audit(&self, _audit: &mut Audit) {
        todo!()
    }
}
