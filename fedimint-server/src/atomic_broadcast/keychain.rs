use std::collections::BTreeMap;
use std::io::Write;

use aleph_bft::Keychain as KeychainTrait;
use fedimint_core::encoding::Encodable;
use fedimint_core::session_outcome::SchnorrSignature;
use fedimint_core::{secp256k1, BitcoinHash, NumPeersExt, PeerId};
use secp256k1::hashes::sha256;
use secp256k1::{schnorr, KeyPair, Message, PublicKey};

use crate::config::ServerConfig;

#[derive(Clone, Debug)]
pub struct Keychain {
    peer_id: PeerId,
    public_keys: BTreeMap<PeerId, PublicKey>,
    keypair: KeyPair,
}

impl Keychain {
    pub fn new(cfg: &ServerConfig) -> Self {
        Keychain {
            peer_id: cfg.local.identity,
            public_keys: cfg.consensus.broadcast_public_keys.clone(),
            keypair: cfg
                .private
                .broadcast_secret_key
                .keypair(secp256k1::SECP256K1),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn peer_count(&self) -> usize {
        self.public_keys.total()
    }

    pub fn threshold(&self) -> usize {
        self.public_keys.threshold()
    }

    fn tagged_hash(&self, message: &[u8]) -> Message {
        let mut engine = sha256::HashEngine::default();

        let public_key_tag = self.public_keys.consensus_hash::<sha256::Hash>();

        engine
            .write_all(public_key_tag.as_ref())
            .expect("Writing to a hash engine can not fail");

        engine
            .write_all(message)
            .expect("Writing to a hash engine can not fail");

        let hash = sha256::Hash::from_engine(engine);

        Message::from(hash)
    }
}

impl aleph_bft::Index for Keychain {
    fn index(&self) -> aleph_bft::NodeIndex {
        self.peer_id.to_usize().into()
    }
}

#[async_trait::async_trait]
impl aleph_bft::Keychain for Keychain {
    type Signature = SchnorrSignature;

    fn node_count(&self) -> aleph_bft::NodeCount {
        self.peer_count().into()
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        SchnorrSignature(
            self.keypair
                .sign_schnorr(self.tagged_hash(message))
                .as_ref()
                .to_owned(),
        )
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &Self::Signature,
        node_index: aleph_bft::NodeIndex,
    ) -> bool {
        let peer_id = super::to_peer_id(node_index);

        if let Some(public_key) = self.public_keys.get(&peer_id) {
            if let Ok(sig) = schnorr::Signature::from_slice(&signature.0) {
                return secp256k1::SECP256K1
                    .verify_schnorr(
                        &sig,
                        &self.tagged_hash(message),
                        &public_key.x_only_public_key().0,
                    )
                    .is_ok();
            }
        }

        false
    }
}

impl aleph_bft::MultiKeychain for Keychain {
    type PartialMultisignature = aleph_bft::NodeMap<SchnorrSignature>;

    fn bootstrap_multi(
        &self,
        signature: &Self::Signature,
        index: aleph_bft::NodeIndex,
    ) -> Self::PartialMultisignature {
        let mut partial = aleph_bft::NodeMap::with_size(self.peer_count().into());
        partial.insert(index, signature.clone());
        partial
    }

    fn is_complete(&self, msg: &[u8], partial: &Self::PartialMultisignature) -> bool {
        if partial.iter().count() < self.threshold() {
            return false;
        }

        partial.iter().all(|(i, sgn)| self.verify(msg, sgn, i))
    }
}
