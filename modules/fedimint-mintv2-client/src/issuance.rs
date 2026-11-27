use bitcoin_hashes::{Hash, hash160, sha256};
use fedimint_client_module::secret::DeriveableSecretClientExt;
use fedimint_core::core::Account;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::rand::Rng;
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_mintv2_common::{Denomination, MintOutput, nonce_message};
use tbs::{BlindedMessage, BlindedSignature, BlindingKey, blind_message, unblind_signature};

use crate::{SpendableNote, thread_rng};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
pub struct NoteIssuanceRequest {
    pub denomination: Denomination,
    pub tweak: [u8; 16],
    pub keypair: Keypair,
    pub blinding_key: BlindingKey,
}

impl NoteIssuanceRequest {
    pub fn new(
        account: Account,
        denomination: Denomination,
        tweak: [u8; 16],
        root_secret: &DerivableSecret,
    ) -> Self {
        let secret = output_secret(account, denomination, tweak, root_secret);

        Self {
            denomination,
            tweak,
            keypair: keypair(&secret),
            blinding_key: blinding_key(&secret),
        }
    }

    pub fn output(&self) -> MintOutput {
        MintOutput::new_v0(self.denomination, self.blinded_message(), self.tweak)
    }

    pub fn finalize(&self, signature: BlindedSignature) -> SpendableNote {
        SpendableNote {
            denomination: self.denomination,
            keypair: self.keypair,
            signature: unblind_signature(self.blinding_key, signature),
        }
    }

    pub fn blinded_message(&self) -> BlindedMessage {
        blind_message(nonce_message(self.keypair.public_key()), self.blinding_key)
    }
}

// ============ Grinding Functions ============

/// Deliberately derived from the module root rather than from an account's
/// subtree, so every account grinds against the same filter.
///
/// One pre-grinder therefore serves the whole wallet instead of one per
/// account, and a recovery still runs a single [`check_tweak`] per output —
/// only the ~1/65536 that pass it are then tried against each account's
/// nonces. It also leaves the filter of a wallet that predates accounts
/// byte-for-byte what it was.
pub fn tweak_filter(root_secret: &DerivableSecret) -> [u8; 32] {
    root_secret.to_random_bytes()
}

pub fn grind_tweak(root_secret: &DerivableSecret) -> [u8; 16] {
    let filter = tweak_filter(root_secret);

    loop {
        let tweak = thread_rng().r#gen();

        if check_tweak(tweak, filter) {
            return tweak;
        }
    }
}

pub fn check_tweak(tweak: [u8; 16], seed: [u8; 32]) -> bool {
    (tweak, seed)
        .consensus_hash::<sha256::Hash>()
        .to_byte_array()
        .iter()
        .take(2)
        .all(|b| *b == 0)
}

// ============ Validation Functions ============

pub fn check_nonce(secret: &OutputSecret, nonce_hash: hash160::Hash) -> bool {
    blinded_message(secret).consensus_hash::<hash160::Hash>() == nonce_hash
}

// ============ Core Crypto Functions ============

pub struct OutputSecret(DerivableSecret);

pub fn output_secret(
    account: Account,
    denomination: Denomination,
    tweak: [u8; 16],
    root: &DerivableSecret,
) -> OutputSecret {
    OutputSecret(
        root.derive_account_secret(account)
            .child_key(ChildId(u64::from(denomination.0)))
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

pub fn blinded_message(secret: &OutputSecret) -> BlindedMessage {
    blind_message(nonce_message(nonce(secret)), blinding_key(secret))
}
