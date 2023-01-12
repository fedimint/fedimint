use std::io;

use fedimint_api::core::PluginDecode;
use fedimint_api::encoding::Decodable;
use fedimint_api::encoding::DecodeError;
use fedimint_api::module::registry::ModuleDecoderRegistry;

use crate::{LightningConsensusItem, LightningInput, LightningOutput, LightningOutputOutcome};

#[derive(Debug, Default, Clone)]
pub struct LightningDecoder;

impl PluginDecode for LightningDecoder {
    type Input = LightningInput;
    type Output = LightningOutput;
    type OutputOutcome = LightningOutputOutcome;
    type ConsensusItem = LightningConsensusItem;

    fn decode_input(&self, mut d: &mut dyn io::Read) -> Result<LightningInput, DecodeError> {
        LightningInput::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_output(&self, mut d: &mut dyn io::Read) -> Result<LightningOutput, DecodeError> {
        LightningOutput::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_output_outcome(
        &self,
        mut d: &mut dyn io::Read,
    ) -> Result<LightningOutputOutcome, DecodeError> {
        LightningOutputOutcome::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_consensus_item(
        &self,
        mut r: &mut dyn io::Read,
    ) -> Result<LightningConsensusItem, DecodeError> {
        LightningConsensusItem::consensus_decode(&mut r, &ModuleDecoderRegistry::default())
    }
}
