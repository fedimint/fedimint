use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::{borrow_slice_impl, hash_newtype, hex_fmt_impl, index_impl, serde_impl};
use serde::{Deserialize, Serialize};

pub use bitcoin_hashes::Hash as BitcoinHash;

hash_newtype!(
    TransactionId,
    Sha256,
    32,
    doc = "A transaction id for peg-ins, peg-outs and reissuances"
);

/// Request to blind sign a certain amount of coins
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SignRequest(pub Vec<tbs::BlindedMessage>);

// FIXME: optimize out blinded msg by making the mint remember it
/// Blind signature share for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PartialSigResponse(pub Vec<(tbs::BlindedMessage, tbs::BlindedSignatureShare)>);

/// Blind signature for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SigResponse(pub Vec<tbs::BlindedSignature>);

/// A cryptographic coin consisting of a token and a threshold signature by the federated mint. In
/// this form it can oly be validated, not spent since for that the corresponding [`musig::SecKey`]
/// is required.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Coin(pub CoinNonce, pub tbs::Signature);

/// A unique coin nonce which is also a MuSig pub key so that transactions can be signed by the
/// spent coin's spending keys to avoid mint frontrunning.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct CoinNonce(pub musig::PubKey);

/// After sending bitcoins to the federation wallet a client can request the appropriate amount
/// of coins in return using this request.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PegInRequest {
    pub blind_tokens: SignRequest,
    pub proof: (), // TODO: implement pegin
}

/// Exchange already signed [`Coin`]s for new coins, breaking the link due to blind signing
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct ReissuanceRequest {
    pub coins: Vec<Coin>,
    pub blind_tokens: SignRequest,
    pub sig: musig::Sig,
}

/// Redeem [`Coin`]s for bitcoin on-chain
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PegOutRequest {
    pub address: (), // TODO: implement pegout
    pub coins: Vec<Coin>,
    pub sig: (), // TODO: impl signing
}

/// This object belongs to an issuance operation and thus has an [`IssuanceId`]
pub trait TxId {
    /// Calculate [`IssuanceId`]
    fn id(&self) -> TransactionId;
}

impl TxId for PegInRequest {
    fn id(&self) -> TransactionId {
        let mut hasher = Sha256::engine();
        bincode::serialize_into(&mut hasher, &self.blind_tokens).expect("encoding error");
        bincode::serialize_into(&mut hasher, &self.proof).expect("encoding error");
        TransactionId(Sha256::from_engine(hasher))
    }
}

impl TxId for ReissuanceRequest {
    fn id(&self) -> TransactionId {
        let mut hasher = Sha256::engine();
        bincode::serialize_into(&mut hasher, &self.coins).expect("encoding error");
        bincode::serialize_into(&mut hasher, &self.blind_tokens).expect("encoding error");
        TransactionId(Sha256::from_engine(hasher))
    }
}

impl TxId for PegOutRequest {
    fn id(&self) -> TransactionId {
        let mut hasher = Sha256::engine();
        bincode::serialize_into(&mut hasher, &self.coins).expect("encoding error");
        bincode::serialize_into(&mut hasher, &self.address).expect("encoding error");
        TransactionId(Sha256::from_engine(hasher))
    }
}

impl Coin {
    /// Verify the coin's validity under a mit key `pk`
    pub fn verify(&self, pk: tbs::AggregatePublicKey) -> bool {
        tbs::verify(self.0.to_message(), self.1, pk)
    }

    /// Access the nonce as the public key to the spend key
    pub fn spend_key(&self) -> &musig::PubKey {
        &self.0 .0
    }
}

impl CoinNonce {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bincode::serialize_into(&mut bytes, &self.0).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn to_message(&self) -> tbs::Message {
        let mut hasher = sha3::Sha3_256::default();
        bincode::serialize_into(&mut hasher, &self.0).unwrap();
        tbs::Message::from_hash(hasher)
    }
}
