use std::{collections::BTreeMap, io};

use fedimint_api::module::{
    ConsensusItem, Input, ModuleKey, Output, OutputOutcome, PendingOutput, PluginConsensusItem,
    PluginDecoder, PluginInput, PluginOutput, PluginOutputOutcome, PluginPendingOutput,
    PluginSpendableOutput, SpendableOutput,
};
use fedimint_api::{
    encoding::{Decodable, DecodeError, Encodable},
    Amount,
};

pub const MINT_MODULE_KEY: u16 = 0;

// TODO: DELME
#[derive(Default, Clone)]
pub struct L1ModuleCommon;

impl PluginDecoder for L1ModuleCommon {
    fn module_key() -> ModuleKey {
        MINT_MODULE_KEY
    }
    fn decode_spendable_output(mut d: &mut dyn io::Read) -> Result<SpendableOutput, DecodeError> {
        Ok(SpendableOutput::from(L1SpendableOutput::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }

    fn decode_pending_output(mut d: &mut dyn io::Read) -> Result<PendingOutput, DecodeError> {
        Ok(PendingOutput::from(L1PendingOutput::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }

    fn decode_output(mut d: &mut dyn io::Read) -> Result<Output, DecodeError> {
        Ok(Output::from(L1Output::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }
    fn decode_output_outcome(mut d: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        Ok(OutputOutcome::from(L1OutputOutcome::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }

    fn decode_input(mut d: &mut dyn io::Read) -> Result<Input, DecodeError> {
        Ok(Input::from(L1Input::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }

    fn decode_consensus_item(mut d: &mut dyn io::Read) -> Result<ConsensusItem, DecodeError> {
        Ok(ConsensusItem::from(L1ConsensusItem::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct L1Output;

impl PluginOutput for L1Output {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct L1PendingOutput;

impl PluginPendingOutput for L1PendingOutput {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct L1OutputOutcome;

impl PluginOutputOutcome for L1OutputOutcome {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn is_final(&self) -> bool {
        true
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct L1SpendableOutput;

impl PluginSpendableOutput for L1SpendableOutput {
    fn module_key(&self) -> ModuleKey {
        todo!()
    }

    fn amount(&self) -> Amount {
        todo!()
    }

    fn key(&self) -> String {
        todo!()
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct L1Input;

impl PluginInput for L1Input {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Encodable, Decodable, Clone, Debug)]
pub struct L1ConsensusItem;

impl PluginConsensusItem for L1ConsensusItem {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn is_final(&self) -> bool {
        true
    }
}
