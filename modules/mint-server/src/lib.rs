use async_trait::async_trait;
use fedimint_api::{
    db::batch::BatchTx,
    module::{audit::Audit, interconnect::ModuleInterconect},
    Amount, OutPoint, PeerId,
};
use fedimint_core_server::{
    ApiEndpoint, ConsensusItem, Error, IServerModule, Input, InputMeta, ModuleCommon, ModuleKey,
    Output, OutputOutcome, SpendableOutput, VerificationCache,
};
use fedimint_mint_common::MintModuleCommon;
use std::{collections::HashSet, io};

#[derive(Default)]
pub struct MintServerModule {
    common: MintModuleCommon,
}

impl MintServerModule {
    pub fn new() -> Self {
        Self {
            common: MintModuleCommon,
        }
    }
}

impl ModuleCommon for MintServerModule {
    fn module_key(&self) -> ModuleKey {
        self.common.module_key()
    }

    fn decode_spendable_output(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<SpendableOutput, fedimint_api::encoding::DecodeError> {
        self.common.decode_spendable_output(r)
    }

    fn decode_output(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<Output, fedimint_api::encoding::DecodeError> {
        self.common.decode_output(r)
    }

    fn decode_input(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<Input, fedimint_api::encoding::DecodeError> {
        self.common.decode_input(r)
    }

    fn decode_pending_output(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<fedimint_core_server::PendingOutput, fedimint_api::encoding::DecodeError> {
        self.common.decode_pending_output(r)
    }

    fn decode_output_outcome(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<fedimint_core_server::OutputOutcome, fedimint_api::encoding::DecodeError> {
        self.common.decode_output_outcome(r)
    }
}

#[async_trait(?Send)]
impl IServerModule for MintServerModule {
    fn init(&self) {
        todo!()
    }

    async fn await_consensus_proposal(&self) {
        todo!()
    }

    async fn consensus_proposal(&self) -> Vec<ConsensusItem> {
        todo!()
    }

    async fn begin_consensus_epoch(
        &self,
        _batch: BatchTx<'_>,
        _consensus_items: Vec<(PeerId, ConsensusItem)>,
    ) {
        todo!()
    }

    fn build_verification_cache(&self, _inputs: &[Input]) -> VerificationCache {
        todo!()
    }

    fn validate_input(
        &self,
        _interconnect: &dyn ModuleInterconect,
        _verification_cache: &VerificationCache,
        _input: &Input,
    ) -> Result<InputMeta, Error> {
        todo!()
    }

    fn apply_input<'a, 'b>(
        &'a self,
        _interconnect: &'a dyn ModuleInterconect,
        _batch: BatchTx<'a>,
        _input: &'b Input,
        _verification_cache: &VerificationCache,
    ) -> Result<InputMeta, Error> {
        todo!()
    }

    fn validate_output(&self, _output: &Output) -> Result<Amount, Error> {
        todo!()
    }

    fn apply_output(
        &self,
        _batch: BatchTx,
        _output: &Output,
        _out_point: OutPoint,
    ) -> Result<Amount, Error> {
        todo!()
    }

    async fn end_consensus_epoch(
        &self,
        _consensus_peers: &HashSet<PeerId>,
        _batch: BatchTx<'_>,
    ) -> Vec<PeerId> {
        todo!()
    }

    fn output_status(&self, _out_point: crate::OutPoint) -> Option<OutputOutcome> {
        todo!()
    }

    fn audit(&self, _audit: &mut Audit) {
        todo!()
    }

    fn api_base_name(&self) -> &'static str {
        todo!()
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint> {
        todo!()
    }
}
