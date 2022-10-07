use std::{collections::BTreeMap, io};

use contracts::{incoming::OfferId, ContractId, ContractOutcome, DecryptedPreimage};
use fedimint_api::module::{
    Input, ModuleKey, Output, OutputOutcome, PendingOutput, PluginDecoder, PluginInput,
    PluginOutput, PluginOutputOutcome, PluginPendingOutput, PluginSpendableOutput, SpendableOutput,
};
use fedimint_api::{
    encoding::{Decodable, DecodeError, Encodable},
    Amount,
};
use serde::{Deserialize, Serialize};

pub mod contracts;

pub const MINT_MODULE_KEY: u16 = 0;

// TODO: DELME
#[derive(Default, Clone)]
pub struct LightningModuleCommon;

impl PluginDecoder for LightningModuleCommon {
    fn module_key() -> ModuleKey {
        MINT_MODULE_KEY
    }
    fn decode_spendable_output(mut d: &mut dyn io::Read) -> Result<SpendableOutput, DecodeError> {
        Ok(SpendableOutput::from(
            LightningSpendableOutput::consensus_decode(&mut d, &BTreeMap::<_, ()>::new())?,
        ))
    }

    fn decode_pending_output(mut d: &mut dyn io::Read) -> Result<PendingOutput, DecodeError> {
        Ok(PendingOutput::from(
            LightningPendingOutput::consensus_decode(&mut d, &BTreeMap::<_, ()>::new())?,
        ))
    }

    fn decode_output(mut d: &mut dyn io::Read) -> Result<Output, DecodeError> {
        Ok(Output::from(LightningOutput::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }
    fn decode_output_outcome(mut d: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        Ok(OutputOutcome::from(
            LightningOutputOutcome::consensus_decode(&mut d, &BTreeMap::<_, ()>::new())?,
        ))
    }

    fn decode_input(mut d: &mut dyn io::Read) -> Result<Input, DecodeError> {
        Ok(Input::from(LightningInput::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct LightningOutput;

impl PluginOutput for LightningOutput {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct LightningPendingOutput;

impl PluginPendingOutput for LightningPendingOutput {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutputOutcome {
    Contract {
        id: ContractId,
        outcome: ContractOutcome,
    },
    Offer {
        id: OfferId,
    },
}
impl PluginOutputOutcome for LightningOutputOutcome {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn is_final(&self) -> bool {
        match self {
            LightningOutputOutcome::Offer { .. } => true,
            LightningOutputOutcome::Contract { outcome, .. } => match outcome {
                ContractOutcome::Account(_) => true,
                ContractOutcome::Incoming(DecryptedPreimage::Some(_)) => true,
                ContractOutcome::Incoming(_) => false,
                ContractOutcome::Outgoing(_) => true,
            },
        }
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct LightningSpendableOutput;

impl PluginSpendableOutput for LightningSpendableOutput {
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
pub struct LightningInput;

impl PluginInput for LightningInput {
    fn module_key(&self) -> ModuleKey {
        MINT_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}
