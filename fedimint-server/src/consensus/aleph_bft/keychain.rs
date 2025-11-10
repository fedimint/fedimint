use std::collections::BTreeMap;
use std::io::Write;

use aleph_bft::Keychain as KeychainTrait;
use bitcoin::hashes::Hash;
use fedimint_core::encoding::Encodable;
use fedimint_core::{NumPeersExt, PeerId, secp256k1};
use secp256k1::hashes::sha256;
use secp256k1::{Keypair, Message, PublicKey, schnorr};

use crate::config::ServerConfig;

#[derive(Clone, Debug)]
pub struct Keychain {
    identity: PeerId,
    pks: BTreeMap<PeerId, PublicKey>,
    message_tag: sha256::Hash,
    keypair: Keypair,
}

impl Keychain {
    pub fn new(cfg: &ServerConfig) -> Self {
        Keychain {
            identity: cfg.local.identity,
            pks: cfg.consensus.broadcast_public_keys.clone(),
            message_tag: cfg.consensus.broadcast_public_keys.consensus_hash(),
            keypair: cfg
                .private
                .broadcast_secret_key
                .keypair(secp256k1::SECP256K1),
        }
    }

    // Tagging messages with the hash of the public key set ensures that peers with
    // an incorrect public key set cannot create signatures that are accepted by
    // their peers.
    fn tagged_message(&self, message: &[u8]) -> Message {
        let mut engine = sha256::HashEngine::default();

        engine
            .write_all(self.message_tag.as_ref())
            .expect("Writing to a hash engine can not fail");

        engine
            .write_all(message)
            .expect("Writing to a hash engine can not fail");

        let hash = sha256::Hash::from_engine(engine);

        Message::from_digest(*hash.as_ref())
    }

    pub fn sign_schnorr(&self, message: &[u8]) -> schnorr::Signature {
        self.keypair.sign_schnorr(self.tagged_message(message))
    }

    pub fn verify_schnorr(
        &self,
        message: &[u8],
        signature: &schnorr::Signature,
        peer_id: PeerId,
    ) -> bool {
        match self.pks.get(&peer_id) {
            Some(public_key) => secp256k1::SECP256K1
                .verify_schnorr(
                    signature,
                    &self.tagged_message(message),
                    &public_key.x_only_public_key().0,
                )
                .is_ok(),
            None => false,
        }
    }
}

impl aleph_bft::Index for Keychain {
    fn index(&self) -> aleph_bft::NodeIndex {
        self.identity.to_usize().into()
    }
}

#[async_trait::async_trait]
impl aleph_bft::Keychain for Keychain {
    type Signature = [u8; 64];

    fn node_count(&self) -> aleph_bft::NodeCount {
        self.pks.len().into()
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        self.sign_schnorr(message).serialize()
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &Self::Signature,
        node_index: aleph_bft::NodeIndex,
    ) -> bool {
        match schnorr::Signature::from_slice(signature) {
            Ok(sig) => self.verify_schnorr(message, &sig, super::to_peer_id(node_index)),
            Err(_) => false,
        }
    }
}

impl aleph_bft::MultiKeychain for Keychain {
    type PartialMultisignature = aleph_bft::NodeMap<[u8; 64]>;

    fn bootstrap_multi(
        &self,
        signature: &Self::Signature,
        index: aleph_bft::NodeIndex,
    ) -> Self::PartialMultisignature {
        let mut partial = aleph_bft::NodeMap::with_size(self.pks.len().into());

        partial.insert(index, *signature);

        partial
    }

    fn is_complete(&self, msg: &[u8], partial: &Self::PartialMultisignature) -> bool {
        if partial.iter().count() < self.pks.to_num_peers().threshold() {
            return false;
        }

        partial.iter().all(|(i, sgn)| self.verify(msg, sgn, i))
    }
}
