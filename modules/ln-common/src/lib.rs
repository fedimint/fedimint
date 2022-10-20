use std::{collections::BTreeMap, io};

use contracts::{incoming::OfferId, ContractId, ContractOutcome, DecryptedPreimage};
use contracts::{Preimage, PreimageDecryptionShare};
use fedimint_api::module::{
    ConsensusItem, Input, ModuleKey, Output, OutputOutcome, PendingOutput, PluginConsensusItem,
    PluginDecoder, PluginInput, PluginOutput, PluginOutputOutcome, PluginPendingOutput,
    PluginSpendableOutput, SpendableOutput,
};
use fedimint_api::{
    encoding::{Decodable, DecodeError, Encodable},
    Amount,
};
use serde::{Deserialize, Serialize};

pub mod contracts;

pub const LN_MODULE_KEY: u16 = 0;

#[derive(Default, Clone)]
pub struct LightningModuleDecoder;

impl PluginDecoder for LightningModuleDecoder {
    fn module_key() -> ModuleKey {
        LN_MODULE_KEY
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
        Ok(Output::from(ContractOrOfferOutput::consensus_decode(
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
        Ok(Input::from(ContractInput::consensus_decode(
            &mut d,
            &BTreeMap::<_, ()>::new(),
        )?))
    }

    fn decode_consensus_item(
        mut r: &mut dyn io::Read,
    ) -> Result<fedimint_api::module::ConsensusItem, DecodeError> {
        Ok(ConsensusItem::from(DecryptionShareCI::consensus_decode(
            &mut r,
            &BTreeMap::<_, ()>::new(),
        )?))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct CDecodableontractOutput {
    pub amount: fedimint_api::Amount,
    pub contract: contracts::Contract,
}

/// Represents an output of the Lightning module.
///
/// There are three sub-types:
///   * Normal contracts users may lock funds in
///   * Offers to buy preimages (see `contracts::incoming` docs)
///   * Early cancellation of outgoing contracts before their timeout
///
/// The offer type exists to register `IncomingContractOffer`s. Instead of patching in a second way
/// of letting clients submit consensus items outside of transactions we let offers be a 0-amount
/// output. We need to take care to allow 0-input, 1-output transactions for that to allow users
/// to receive their fist tokens via LN without already having tokens.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum ContractOrOfferOutput {
    /// Fund contract
    Contract(ContractOutput),
    /// Creat incoming contract offer
    Offer(contracts::incoming::IncomingContractOffer),
    /// Allow early refund of outgoing contract
    CancelOutgoing {
        /// Contract to update
        contract: ContractId,
        /// Signature of gateway
        gateway_signature: secp256k1::schnorr::Signature,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractOutput {
    pub amount: fedimint_api::Amount,
    pub contract: contracts::Contract,
}

#[derive(Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize, Clone)]
pub struct ContractAccount {
    pub amount: fedimint_api::Amount,
    pub contract: contracts::FundedContract,
}

impl PluginOutput for ContractOrOfferOutput {
    fn module_key(&self) -> ModuleKey {
        LN_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Encodable, Decodable, Clone)]
pub struct LightningPendingOutput;

impl PluginPendingOutput for LightningPendingOutput {
    fn module_key(&self) -> ModuleKey {
        LN_MODULE_KEY
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
        LN_MODULE_KEY
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractInput {
    pub contract_id: contracts::ContractId,
    /// While for now we only support spending the entire contract we need to avoid
    pub amount: Amount,
    /// Of the three contract types only the outgoing one needs any other witness data than a
    /// signature. The signature is aggregated on the transaction level, so only the optional
    /// preimage remains.
    pub witness: Option<Preimage>,
}

impl PluginInput for ContractInput {
    fn module_key(&self) -> ModuleKey {
        LN_MODULE_KEY
    }

    fn amount(&self) -> Amount {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct DecryptionShareCI {
    pub contract_id: ContractId,
    pub share: PreimageDecryptionShare,
}

impl PluginConsensusItem for DecryptionShareCI {
    fn module_key(&self) -> ModuleKey {
        LN_MODULE_KEY
    }

    fn is_final(&self) -> bool {
        todo!()
    }
}
