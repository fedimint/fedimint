use std::io;

use fedimint_api::core::Decoder;
use fedimint_api::encoding::{Decodable, DecodeError};
use fedimint_api::module::registry::ModuleDecoderRegistry;

use crate::{PoolConsensusItem, PoolInput, PoolOutput, PoolOutputOutcome};

#[derive(Debug, Default, Clone)]
pub struct PoolDecoder;

impl Decoder for PoolDecoder {
    type Input = PoolInput;
    type Output = PoolOutput;
    type OutputOutcome = PoolOutputOutcome;
    type ConsensusItem = PoolConsensusItem;

    fn decode_input(&self, mut d: &mut dyn io::Read) -> Result<PoolInput, DecodeError> {
        PoolInput::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_output(&self, mut d: &mut dyn io::Read) -> Result<PoolOutput, DecodeError> {
        PoolOutput::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_output_outcome(
        &self,
        mut d: &mut dyn io::Read,
    ) -> Result<PoolOutputOutcome, DecodeError> {
        PoolOutputOutcome::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_consensus_item(
        &self,
        mut r: &mut dyn io::Read,
    ) -> Result<PoolConsensusItem, DecodeError> {
        PoolConsensusItem::consensus_decode(&mut r, &ModuleDecoderRegistry::default())
    }
}
