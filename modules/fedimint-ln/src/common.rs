use std::io;

use fedimint_api::core::{ConsensusItem, Input, Output, OutputOutcome, PluginDecode};
use fedimint_api::encoding::Decodable;
use fedimint_api::encoding::DecodeError;
use fedimint_api::module::registry::ModuleDecoderRegistry;

use crate::{LightningConsensusItem, LightningInput, LightningOutput, LightningOutputOutcome};

#[derive(Debug, Default, Clone)]
pub struct LightningModuleDecoder;

impl PluginDecode for LightningModuleDecoder {
    fn decode_input(mut d: &mut dyn io::Read) -> Result<Input, DecodeError> {
        Ok(Input::from(LightningInput::consensus_decode(
            &mut d,
            &ModuleDecoderRegistry::default(),
        )?))
    }
    fn decode_output(mut d: &mut dyn io::Read) -> Result<Output, DecodeError> {
        Ok(Output::from(LightningOutput::consensus_decode(
            &mut d,
            &ModuleDecoderRegistry::default(),
        )?))
    }

    fn decode_output_outcome(mut d: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        Ok(OutputOutcome::from(
            LightningOutputOutcome::consensus_decode(&mut d, &ModuleDecoderRegistry::default())?,
        ))
    }

    fn decode_consensus_item(
        mut r: &mut dyn io::Read,
    ) -> Result<fedimint_api::core::ConsensusItem, DecodeError> {
        Ok(ConsensusItem::from(
            LightningConsensusItem::consensus_decode(&mut r, &ModuleDecoderRegistry::default())?,
        ))
    }
}
