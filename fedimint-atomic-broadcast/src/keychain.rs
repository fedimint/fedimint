use std::collections::BTreeMap;
use std::io::Write;

use aleph_bft::Keychain as KeychainTrait;
use fedimint_core::block::consensus_hash_sha256;
use fedimint_core::{BitcoinHash, PeerId};
use secp256k1_zkp::hashes::sha256;
use secp256k1_zkp::{schnorr, All, KeyPair, Message, PublicKey, Secp256k1, SecretKey};

use crate::conversion;

#[derive(Clone, Debug)]
pub struct Keychain {
    peer_id: PeerId,
    public_keys: BTreeMap<PeerId, secp256k1_zkp::PublicKey>,
    keypair: KeyPair,
    secp: Secp256k1<All>,
}

impl Keychain {
    pub fn new(
        peer_id: PeerId,
        public_keys: BTreeMap<PeerId, PublicKey>,
        secret_key: SecretKey,
    ) -> Self {
        let secp = Secp256k1::new();
        let keypair = secret_key.keypair(&secp);

        Keychain {
            peer_id,
            public_keys,
            keypair,
            secp,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn peer_count(&self) -> usize {
        self.public_keys.len()
    }

    pub fn threshold(&self) -> usize {
        (2 * self.peer_count()) / 3 + 1
    }

    fn tagged_hash(&self, message: &[u8]) -> Message {
        let public_key_tag = consensus_hash_sha256(&self.public_keys);
        let mut engine = sha256::HashEngine::default();

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
    type Signature = [u8; 64];

    fn node_count(&self) -> aleph_bft::NodeCount {
        self.peer_count().into()
    }

    async fn sign(&self, message: &[u8]) -> Self::Signature {
        self.secp
            .sign_schnorr(&self.tagged_hash(message), &self.keypair)
            .as_ref()
            .to_owned()
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &Self::Signature,
        node_index: aleph_bft::NodeIndex,
    ) -> bool {
        let peer_id = conversion::to_peer_id(node_index);

        if let Some(public_key) = self.public_keys.get(&peer_id) {
            if let Ok(sig) = schnorr::Signature::from_slice(signature) {
                return self
                    .secp
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
    type PartialMultisignature = aleph_bft::NodeMap<[u8; 64]>;

    fn bootstrap_multi(
        &self,
        signature: &Self::Signature,
        index: aleph_bft::NodeIndex,
    ) -> Self::PartialMultisignature {
        let mut partial = aleph_bft::NodeMap::with_size(self.peer_count().into());
        partial.insert(index, *signature);
        partial
    }

    fn is_complete(&self, msg: &[u8], partial: &Self::PartialMultisignature) -> bool {
        if partial.iter().count() < self.threshold() {
            return false;
        }

        partial.iter().all(|(i, sgn)| self.verify(msg, sgn, i))
    }
}
