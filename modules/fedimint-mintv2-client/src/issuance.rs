use bitcoin_hashes::{hash160, sha256};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::rand::Rng;
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_mintv2_common::{Denomination, MintOutput};
use tbs::{
    BlindedMessage, BlindedSignature, BlindingKey, Message, blind_message, unblind_signature,
};

use crate::{SpendableNote, thread_rng};

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
            blinded_message(&output_secret(self.denomination, self.tweak, root_secret)),
            self.tweak,
        )
    }

    pub fn finalize(&self, root: &DerivableSecret, signature: BlindedSignature) -> SpendableNote {
        SpendableNote {
            denomination: self.denomination,
            signature: unblind_signature(blinding_key(&self.output_secret(root)), signature),
            keypair: keypair(&self.output_secret(root)),
        }
    }

    fn output_secret(&self, root_secret: &DerivableSecret) -> OutputSecret {
        output_secret(self.denomination, self.tweak, root_secret)
    }
}

// ============ Grinding Functions ============

pub fn grind_tweak(root_secret: &DerivableSecret) -> [u8; 12] {
    let seed = root_secret.to_random_bytes::<32>();

    loop {
        let tweak = thread_rng().r#gen();

        if check_tweak(tweak, seed) {
            return tweak;
        }
    }
}

pub fn check_tweak(tweak: [u8; 12], seed: [u8; 32]) -> bool {
    (tweak, seed).consensus_hash::<sha256::Hash>()[0] == 0
}

// ============ Validation Functions ============

pub fn check_nonce(secret: &OutputSecret, nonce_hash: hash160::Hash) -> bool {
    blinded_message(secret).consensus_hash::<hash160::Hash>() == nonce_hash
}

// ============ Core Crypto Functions ============

pub struct OutputSecret(DerivableSecret);

pub fn output_secret(
    denomination: Denomination,
    tweak: [u8; 12],
    root: &DerivableSecret,
) -> OutputSecret {
    OutputSecret(
        root.child_key(ChildId(u64::from(denomination.0)))
            .tweak(&tweak),
    )
}

fn keypair(secret: &OutputSecret) -> Keypair {
    secret.0.clone().to_secp_key(SECP256K1)
}

pub fn nonce(secret: &OutputSecret) -> PublicKey {
    keypair(secret).public_key()
}

fn blinding_key(secret: &OutputSecret) -> BlindingKey {
    BlindingKey(secret.0.to_bls12_381_key())
}

fn message(secret: &OutputSecret) -> Message {
    Message::from_bytes_sha256(&nonce(secret).serialize())
}

pub fn blinded_message(secret: &OutputSecret) -> BlindedMessage {
    blind_message(message(secret), blinding_key(secret))
}
