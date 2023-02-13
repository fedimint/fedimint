use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::Amount;
use serde::Serialize;

use crate::modules::ln::contracts::outgoing::OutgoingContract;
use crate::modules::ln::contracts::{IdentifyableContract, Preimage};
use crate::modules::ln::LightningInput;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OutgoingContractData {
    pub recovery_key: bitcoin::KeyPair,
    pub contract_account: OutgoingContractAccount,
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OutgoingContractAccount {
    pub amount: Amount,
    pub contract: OutgoingContract,
}

impl OutgoingContractAccount {
    pub fn claim(&self, preimage: Preimage) -> LightningInput {
        LightningInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: Some(preimage),
        }
    }

    pub fn refund(&self) -> LightningInput {
        LightningInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: None,
        }
    }
}
