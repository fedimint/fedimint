use std::io;

use fedimint_api::core::PluginDecode;
use fedimint_api::encoding::{Decodable, DecodeError};
use fedimint_api::module::registry::ModuleDecoderRegistry;

use crate::{WalletConsensusItem, WalletInput, WalletOutput, WalletOutputOutcome};

#[derive(Debug, Default, Clone)]
pub struct WalletDecoder;

impl PluginDecode for WalletDecoder {
    type Input = WalletInput;
    type Output = WalletOutput;
    type OutputOutcome = WalletOutputOutcome;
    type ConsensusItem = WalletConsensusItem;

    fn decode_input(&self, mut d: &mut dyn io::Read) -> Result<WalletInput, DecodeError> {
        WalletInput::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_output(&self, mut d: &mut dyn io::Read) -> Result<WalletOutput, DecodeError> {
        WalletOutput::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_output_outcome(
        &self,
        mut d: &mut dyn io::Read,
    ) -> Result<WalletOutputOutcome, DecodeError> {
        WalletOutputOutcome::consensus_decode(&mut d, &ModuleDecoderRegistry::default())
    }

    fn decode_consensus_item(
        &self,
        mut r: &mut dyn io::Read,
    ) -> Result<WalletConsensusItem, DecodeError> {
        WalletConsensusItem::consensus_decode(&mut r, &ModuleDecoderRegistry::default())
    }
}
