use std::io;

use fedimint_api::core::{ConsensusItem, Input, Output, OutputOutcome, PluginDecode};
use fedimint_api::encoding::{Decodable, DecodeError};
use fedimint_api::module::registry::ModuleDecoderRegistry;

use crate::{WalletConsensusItem, WalletInput, WalletOutput, WalletOutputOutcome};

#[derive(Debug, Default, Clone)]
pub struct WalletModuleDecoder;

impl PluginDecode for WalletModuleDecoder {
    fn decode_input(mut d: &mut dyn io::Read) -> Result<Input, DecodeError> {
        Ok(Input::from(WalletInput::consensus_decode(
            &mut d,
            &ModuleDecoderRegistry::default(),
        )?))
    }
    fn decode_output(mut d: &mut dyn io::Read) -> Result<Output, DecodeError> {
        Ok(Output::from(WalletOutput::consensus_decode(
            &mut d,
            &ModuleDecoderRegistry::default(),
        )?))
    }

    fn decode_output_outcome(mut d: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        Ok(OutputOutcome::from(WalletOutputOutcome::consensus_decode(
            &mut d,
            &ModuleDecoderRegistry::default(),
        )?))
    }

    fn decode_consensus_item(
        mut r: &mut dyn io::Read,
    ) -> Result<fedimint_api::core::ConsensusItem, DecodeError> {
        Ok(ConsensusItem::from(WalletConsensusItem::consensus_decode(
            &mut r,
            &ModuleDecoderRegistry::default(),
        )?))
    }
}
