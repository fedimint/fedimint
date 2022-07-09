use crate::contracts::{ContractId, IdentifyableContract};
use bitcoin_hashes::{sha256, Hash};
use minimint_api::encoding::{Decodable, Encodable};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

/// Specialized smart contract for outgoing payments.
///
/// A user locks up funds that can be claimed by a lightning gateway if it pays the invoice and
/// thus receives the preimage to the payment hash and can thereby prove the payment. If the gateway
/// is not able to do so before the timelock expires the user can claim back the funds.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutgoingContract {
    /// Hash that can be used to spend the output before the timelock expires
    pub hash: sha256::Hash,
    /// Public key of the LN gateway allowed to claim the HTLC before the timelock expires
    pub gateway_key: XOnlyPublicKey,
    /// Block height at which the money will be spendable by the pubkey
    pub timelock: u32,
    /// Public key of the user that can claim the money back after the timelock expires
    pub user_key: XOnlyPublicKey,
    // FIXME: use pruned, privacy friendly version without description etc.
    /// Invoice containing metadata on how to obtain the preimage
    pub invoice: String,
}

/// Preimage in the context of [`OutgoingContract`]s
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Preimage(pub [u8; 32]);

impl IdentifyableContract for OutgoingContract {
    fn contract_id(&self) -> ContractId {
        let mut engine = ContractId::engine();
        Encodable::consensus_encode(self, &mut engine).expect("Hashing never fails");
        ContractId::from_engine(engine)
    }
}
