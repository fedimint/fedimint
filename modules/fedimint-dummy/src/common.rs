use std::io;

use fedimint_api::core::PluginDecode;
use fedimint_api::encoding::{Decodable, DecodeError};
use fedimint_api::module::registry::ModuleDecoderRegistry;

use crate::{DummyInput, DummyOutput, DummyOutputConfirmation, DummyOutputOutcome};

#[derive(Debug, Default, Clone)]
pub struct DummyDecoder;

impl PluginDecode for DummyDecoder {
    type Input = DummyInput;
    type Output = DummyOutput;
    type OutputOutcome = DummyOutputOutcome;
    type ConsensusItem = DummyOutputConfirmation;

    fn decode_input(&self, mut d: &mut dyn io::Read) -> Result<DummyInput, DecodeError> {
        DummyInput::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_output(&self, mut d: &mut dyn io::Read) -> Result<DummyOutput, DecodeError> {
        DummyOutput::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_output_outcome(
        &self,
        mut d: &mut dyn io::Read,
    ) -> Result<DummyOutputOutcome, DecodeError> {
        DummyOutputOutcome::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_consensus_item(
        &self,
        mut r: &mut dyn io::Read,
    ) -> Result<DummyOutputConfirmation, DecodeError> {
        DummyOutputConfirmation::consensus_decode(&mut r, &ModuleDecoderRegistry::default())
    }
}
