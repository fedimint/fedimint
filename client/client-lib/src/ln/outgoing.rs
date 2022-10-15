use fedimint_api::encoding::{Decodable, Encodable, ModuleRegistry};
use fedimint_api::Amount;
use fedimint_core::modules::ln::contracts::{
    outgoing::OutgoingContract, IdentifyableContract, Preimage,
};
use fedimint_core::modules::ln::ContractInput;

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractData {
    pub recovery_key: bitcoin::KeyPair,
    pub contract_account: OutgoingContractAccount,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct OutgoingContractAccount {
    pub amount: Amount,
    pub contract: OutgoingContract,
}

impl OutgoingContractAccount {
    pub fn claim(&self, preimage: Preimage) -> ContractInput {
        ContractInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: Some(preimage),
        }
    }

    pub fn refund(&self) -> ContractInput {
        ContractInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: None,
        }
    }
}
