use bitcoin_hashes::{sha256, Hash};
use fedimint_core::encoding::{Decodable, Encodable};
use jsonrpsee_core::Serialize;
use serde::Deserialize;
use url::Url;

use crate::PeerId;

const API_ANNOUNCEMENT_MESSAGE_TAG: &[u8] = b"fedimint-api-announcement";

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Encodable, Decodable)]
pub struct ApiAnnouncement {
    pub api_url: Url,
    pub peer: PeerId,
    pub nonce: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Encodable, Decodable)]
pub struct SignedApiAnnouncement {
    pub api_announcement: ApiAnnouncement,
    pub signature: secp256k1::schnorr::Signature,
}

impl ApiAnnouncement {
    pub fn new(api_url: Url, peer: PeerId, nonce: u64) -> Self {
        Self {
            api_url,
            peer,
            nonce,
        }
    }

    pub fn tagged_hash(&self) -> sha256::Hash {
        let mut msg = API_ANNOUNCEMENT_MESSAGE_TAG.to_vec();
        self.consensus_encode(&mut msg)
            .expect("writing to vec is infallible");
        sha256::Hash::hash(&msg)
    }

    pub fn sign<C: secp256k1::Signing>(
        &self,
        ctx: &secp256k1::Secp256k1<C>,
        key: &secp256k1::KeyPair,
    ) -> SignedApiAnnouncement {
        let msg = self.tagged_hash().into();
        let signature = ctx.sign_schnorr(&msg, key);
        SignedApiAnnouncement {
            api_announcement: self.clone(),
            signature,
        }
    }
}
