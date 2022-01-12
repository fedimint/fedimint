use minimint::modules::ln::contracts::outgoing::{OutgoingContract, Preimage};
use minimint::modules::ln::contracts::IdentifyableContract;
use minimint::modules::ln::ContractInput;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::Amount;

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractData {
    pub recovery_key: secp256k1_zkp::schnorrsig::KeyPair,
    pub contract_account: OutgoingContractAccount,
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutgoingContractAccount {
    pub amount: Amount,
    pub contract: OutgoingContract,
}

impl OutgoingContractAccount {
    #[allow(dead_code)]
    pub fn claim(&self, preimage: [u8; 32]) -> ContractInput {
        ContractInput {
            crontract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: Some(Preimage(preimage)),
        }
    }

    pub fn refund(&self) -> ContractInput {
        ContractInput {
            crontract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: None,
        }
    }
}
