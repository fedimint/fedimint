use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Unique ID for an issuance operation (peg-in or reissuance). This is used to identify the
/// request in subsequent parts of the blind signing protocol
pub type IssuanceId = u64;

/// Request to blind sign a certain amount of coins
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SignRequest(pub Vec<tbs::BlindedMessage>);

// FIXME: optimize out blinded msg by making the mint remember it
/// Blind signature share for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PartialSigResponse(pub Vec<(tbs::BlindedMessage, tbs::BlindedSignatureShare)>);

/// Blind signature for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SigResponse(pub u64, pub Vec<tbs::BlindedSignature>);

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
pub trait RequestId {
    /// Calculate [`IssuanceId`]
    fn id(&self) -> IssuanceId;
}

impl RequestId for SignRequest {
    fn id(&self) -> IssuanceId {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

impl RequestId for PartialSigResponse {
    fn id(&self) -> IssuanceId {
        let mut hasher = DefaultHasher::new();
        self.0
            .iter()
            .map(|(msg, _)| msg)
            .collect::<Vec<_>>()
            .hash(&mut hasher);
        hasher.finish()
    }
}

impl RequestId for SigResponse {
    fn id(&self) -> IssuanceId {
        self.0
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
    pub fn to_message(&self) -> tbs::Message {
        let mut hasher = sha3::Sha3_256::default();
        bincode::serialize_into(&mut hasher, &self.0).unwrap();
        tbs::Message::from_hash(hasher)
    }
}

impl ReissuanceRequest {
    pub fn digest(&self) -> sha3::Sha3_256 {
        let mut digest = sha3::Sha3_256::default();
        bincode::serialize_into(&mut digest, &self.coins).unwrap();
        bincode::serialize_into(&mut digest, &self.blind_tokens).unwrap();
        digest
    }
}
