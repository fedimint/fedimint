use bitcoin::secp256k1::KeyPair;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::Amount;
use fedimint_core::modules::ln::contracts::incoming::IncomingContract;
use fedimint_core::modules::ln::contracts::{ContractId, IdentifyableContract};
use fedimint_core::modules::ln::ContractInput;
use lightning_invoice::Invoice;

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

// TODO: should this have some kind of "state" enum - e.g. pending, paid, expired
/// Invoice whose "offer" has been accepted by federation
#[derive(Debug, Encodable, Decodable)]
pub struct ConfirmedInvoice {
    /// The invoice itself
    pub invoice: Invoice,
    /// Keypair that will be able to sweep contract once it has received payment
    pub keypair: KeyPair,
}

impl ConfirmedInvoice {
    pub fn contract_id(&self) -> ContractId {
        // FIXME: Should we be using the payment hash?
        (*self.invoice.payment_hash()).into()
    }
}
