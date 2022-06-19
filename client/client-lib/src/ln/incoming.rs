use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::Amount;
use minimint_core::modules::ln::contracts::incoming::IncomingContract;
use minimint_core::modules::ln::contracts::IdentifyableContract;
use minimint_core::modules::ln::ContractInput;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct IncomingContractAccount {
    pub amount: Amount,
    pub contract: IncomingContract,
}

impl IncomingContractAccount {
    pub fn claim(&self) -> ContractInput {
        ContractInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: None,
        }
    }
}
