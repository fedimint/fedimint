use bitcoin::secp256k1::KeyPair;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::Amount;
use lightning_invoice::Bolt11Invoice;
use serde::Serialize;

use crate::modules::ln::contracts::incoming::IncomingContract;
use crate::modules::ln::contracts::{ContractId, IdentifiableContract};
use crate::modules::ln::LightningInput;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct IncomingContractAccount {
    pub amount: Amount,
    pub contract: IncomingContract,
}

impl IncomingContractAccount {
    pub fn claim(&self) -> LightningInput {
        LightningInput {
            contract_id: self.contract.contract_id(),
            amount: self.amount,
            witness: None,
        }
    }
}

// TODO: should this have some kind of "state" enum - e.g. pending, paid,
// expired
/// Invoice whose "offer" has been accepted by federation
#[derive(Debug, Encodable, Decodable)]
pub struct ConfirmedInvoice {
    /// The invoice itself
    pub invoice: Bolt11Invoice,
    /// Keypair that will be able to sweep contract once it has received payment
    pub keypair: KeyPair,
}

impl Serialize for ConfirmedInvoice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.invoice.to_string().as_str())
    }
}

impl ConfirmedInvoice {
    pub fn contract_id(&self) -> ContractId {
        // FIXME: Should we be using the payment hash?
        (*self.invoice.payment_hash()).into()
    }
}
