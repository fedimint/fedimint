use std::io;

use fedimint_core::core::Decoder;
use fedimint_core::encoding::{Decodable, DecodeError};
use fedimint_core::module::registry::ModuleDecoderRegistry;

use crate::{DummyConsensusItem, DummyInput, DummyOutput, DummyOutputOutcome};

#[derive(Debug, Default, Clone)]
pub struct DummyDecoder;

impl Decoder for DummyDecoder {
    type Input = DummyInput;
    type Output = DummyOutput;
    type OutputOutcome = DummyOutputOutcome;
    type ConsensusItem = DummyConsensusItem;

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
    ) -> Result<DummyConsensusItem, DecodeError> {
        DummyConsensusItem::consensus_decode(&mut r, &ModuleDecoderRegistry::default())
    }
}
