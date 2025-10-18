use bitcoin_hashes::{hash160, sha256};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::rand::Rng;
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::{Denomination, MintOutput};
use tbs::{
    blind_message, unblind_signature, BlindedMessage, BlindedSignature, BlindingKey, Message,
};

use crate::{thread_rng, SpendableNote};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
pub struct NoteIssuanceRequest {
    pub denomination: Denomination,
    pub tweak: [u8; 12],
}

impl NoteIssuanceRequest {
    pub fn new(denomination: Denomination, tweak: [u8; 12]) -> Self {
        Self {
            denomination,
            tweak,
        }
    }

    pub fn output(&self, root_secret: &DerivableSecret) -> MintOutput {
        MintOutput::new_v0(
            self.denomination,
            blinded_message(self.tweak, root_secret),
            self.tweak,
        )
    }

    pub fn finalize(
        &self,
        root_secret: &DerivableSecret,
        blinded_signature: BlindedSignature,
    ) -> SpendableNote {
        SpendableNote {
            denomination: self.denomination,
            signature: unblind_signature(blinding_key(self.tweak, root_secret), blinded_signature),
            keypair: keypair(self.tweak, root_secret),
        }
    }
}

// ============ Grinding Functions ============

pub fn grind_tweak(root_secret: &DerivableSecret) -> [u8; 12] {
    let seed = root_secret.to_random_bytes::<32>();

    loop {
        let tweak = thread_rng().gen();

        if check_tweak(tweak, seed) {
            return tweak;
        }
    }
}

pub fn check_tweak(tweak: [u8; 12], seed: [u8; 32]) -> bool {
    (tweak, seed).consensus_hash::<sha256::Hash>()[0] == 0
}

// ============ Validation Functions ============

pub fn check_nonce(tweak: [u8; 12], root: &DerivableSecret, nonce_hash: hash160::Hash) -> bool {
    blinded_message(tweak, root).consensus_hash::<hash160::Hash>() == nonce_hash
}

// ============ Core Crypto Functions ============

fn keypair(tweak: [u8; 12], root: &DerivableSecret) -> Keypair {
    root.tweak(&tweak).to_secp_key(SECP256K1)
}

pub fn nonce(tweak: [u8; 12], root: &DerivableSecret) -> PublicKey {
    keypair(tweak, root).public_key()
}

fn blinding_key(tweak: [u8; 12], root: &DerivableSecret) -> BlindingKey {
    BlindingKey(root.tweak(&tweak).to_bls12_381_key())
}

fn message(tweak: [u8; 12], root: &DerivableSecret) -> Message {
    Message::from_bytes_sha256(&nonce(tweak, root).serialize())
}

pub fn blinded_message(tweak: [u8; 12], root: &DerivableSecret) -> BlindedMessage {
    blind_message(message(tweak, root), blinding_key(tweak, root))
}
