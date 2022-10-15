use std::{collections::BTreeMap, io};

use fedimint_api::{
    encoding::{Decodable, DecodeError, Encodable, ModuleRegistry},
    Amount,
};
use fedimint_core_api::{
    Input, ModuleCommon, ModuleKey, Output, OutputOutcome, PendingOutput, PluginInput,
    PluginOutput, PluginOutputOutcome, PluginPendingOutput, PluginSpendableOutput, SpendableOutput,
};

pub const MINT_MODULE_KEY: u16 = 0;

// TODO: DELME
#[derive(Default, Clone)]
pub struct MintModuleCommon;

impl ModuleCommon for MintModuleCommon {
    fn module_key() -> ModuleKey {
        MINT_MODULE_KEY
    }
    fn decode_spendable_output(mut d: &mut dyn io::Read) -> Result<SpendableOutput, DecodeError> {
        Ok(SpendableOutput::from(
            MintSpendableOutput::consensus_decode(&mut d, &BTreeMap::<_, ()>::new())?,
        ))
    }

    fn decode_pending_output(mut d: &mut dyn io::Read) -> Result<PendingOutput, DecodeError> {
        Ok(PendingOutput::from(MintPendingOutput::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }

    fn decode_output(mut d: &mut dyn io::Read) -> Result<Output, DecodeError> {
        Ok(Output::from(MintOutput::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }
    fn decode_output_outcome(mut d: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        Ok(OutputOutcome::from(MintOutputOutcome::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }

    fn decode_input(mut d: &mut dyn io::Read) -> Result<Input, DecodeError> {
        Ok(Input::from(MintInput::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct MintOutput;

impl PluginOutput for MintOutput {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct MintPendingOutput;

impl PluginPendingOutput for MintPendingOutput {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct MintOutputOutcome;

impl PluginOutputOutcome for MintOutputOutcome {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct MintSpendableOutput;

impl PluginSpendableOutput for MintSpendableOutput {
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
pub struct MintInput;

impl PluginInput for MintInput {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}
