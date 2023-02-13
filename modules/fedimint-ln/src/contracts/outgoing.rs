use bitcoin_hashes::Hash as BitcoinHash;
use fedimint_core::encoding::{Decodable, Encodable};
use serde::{Deserialize, Serialize};

use crate::contracts::{ContractId, IdentifyableContract};

const CANCELLATION_TAG: &str = "outgoing contract cancellation";

/// Specialized smart contract for outgoing payments.
///
/// A user locks up funds that can be claimed by a lightning gateway if it pays
/// the invoice and thus receives the preimage to the payment hash and can
/// thereby prove the payment. If the gateway is not able to do so before the
/// timelock expires the user can claim back the funds.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutgoingContract {
    /// Hash that can be used to spend the output before the timelock expires
    pub hash: bitcoin_hashes::sha256::Hash,
    /// Public key of the LN gateway allowed to claim the HTLC before the
    /// timelock expires
    pub gateway_key: secp256k1::XOnlyPublicKey,
    /// Block height at which the money will be spendable by the pubkey
    pub timelock: u32,
    /// Public key of the user that can claim the money back after the timelock
    /// expires
    pub user_key: secp256k1::XOnlyPublicKey,
    // FIXME: use pruned, privacy friendly version without description etc.
    /// Invoice containing metadata on how to obtain the preimage
    pub invoice: lightning_invoice::Invoice,
    /// Flag that can be set by the gateway and allows the client to claim an
    /// early refund
    pub cancelled: bool,
}

impl IdentifyableContract for OutgoingContract {
    fn contract_id(&self) -> ContractId {
        let mut engine = ContractId::engine();
        Encodable::consensus_encode(&self.hash, &mut engine).expect("Hashing never fails");
        Encodable::consensus_encode(&self.gateway_key, &mut engine).expect("Hashing never fails");
        Encodable::consensus_encode(&self.timelock, &mut engine).expect("Hashing never fails");
        Encodable::consensus_encode(&self.user_key, &mut engine).expect("Hashing never fails");
        Encodable::consensus_encode(&self.invoice, &mut engine).expect("Hashing never fails");
        ContractId::from_engine(engine)
    }
}

impl OutgoingContract {
    pub fn cancellation_message(&self) -> bitcoin_hashes::sha256::Hash {
        let mut engine = bitcoin_hashes::sha256::Hash::engine();
        Encodable::consensus_encode(&CANCELLATION_TAG.as_bytes(), &mut engine)
            .expect("Hashing never fails");
        Encodable::consensus_encode(&self.contract_id(), &mut engine).expect("Hashing never fails");
        bitcoin_hashes::sha256::Hash::from_engine(engine)
    }
}
