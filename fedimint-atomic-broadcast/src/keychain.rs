use std::collections::BTreeMap;

use aleph_bft::Keychain as KeychainTrait;
use fedimint_core::PeerId;
use secp256k1::hashes::sha256;
use secp256k1::{schnorr, Message};

use crate::conversion;

#[derive(Clone, Debug)]
pub struct Keychain {
    peer_id: PeerId,
    public_keys: BTreeMap<PeerId, secp256k1::XOnlyPublicKey>,
    keypair: secp256k1::KeyPair,
    secp: secp256k1::Secp256k1<secp256k1::All>,
}

impl Keychain {
    pub fn new(
        peer_id: PeerId,
        public_keys: BTreeMap<PeerId, secp256k1::XOnlyPublicKey>,
        secret_key: secp256k1::SecretKey,
    ) -> Self {
        let secp = secp256k1::Secp256k1::new();
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
        let message = Message::from_hashed_data::<sha256::Hash>(message);

        self.secp
            .sign_schnorr(&message, &self.keypair)
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
                let message = Message::from_hashed_data::<sha256::Hash>(message);

                return self.secp.verify_schnorr(&sig, &message, public_key).is_ok();
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
        partial.iter().count() >= self.threshold()
            && partial.iter().all(|(i, sig)| self.verify(msg, sig, i))
    }
}
