use std::collections::BTreeMap;

use bitcoin30::hashes::{sha256, Hash};
use fedimint_core::db::DatabaseLookup;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::MaybeSend;
use fedimint_core::PeerId;
use futures::StreamExt;
use jsonrpsee_core::Serialize;
use secp256k1::{Message, Verification};
use serde::Deserialize;

use crate::bitcoin_migration::{
    bitcoin30_to_bitcoin32_secp256k1_message, bitcoin32_to_bitcoin30_schnorr_signature,
};
use crate::db::{
    Database, DatabaseKey, DatabaseKeyPrefix, DatabaseRecord, IDatabaseTransactionOpsCoreTyped,
};
use crate::task::MaybeSync;
use crate::util::SafeUrl;

const API_ANNOUNCEMENT_MESSAGE_TAG: &[u8] = b"fedimint-api-announcement";

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Encodable, Decodable)]
pub struct ApiAnnouncement {
    pub api_url: SafeUrl,
    pub nonce: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Encodable, Decodable)]
pub struct SignedApiAnnouncement {
    pub api_announcement: ApiAnnouncement,
    pub signature: secp256k1_29::schnorr::Signature,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Encodable, Decodable)]
pub struct SignedApiAnnouncementSubmission {
    #[serde(flatten)]
    pub signed_api_announcement: SignedApiAnnouncement,
    pub peer_id: PeerId,
}

impl ApiAnnouncement {
    pub fn new(api_url: SafeUrl, nonce: u64) -> Self {
        Self { api_url, nonce }
    }

    pub fn tagged_hash(&self) -> sha256::Hash {
        let mut msg = API_ANNOUNCEMENT_MESSAGE_TAG.to_vec();
        self.consensus_encode(&mut msg)
            .expect("writing to vec is infallible");
        sha256::Hash::hash(&msg)
    }

    pub fn sign<C: secp256k1_29::Signing>(
        &self,
        ctx: &secp256k1_29::Secp256k1<C>,
        key: &secp256k1_29::Keypair,
    ) -> SignedApiAnnouncement {
        let msg = bitcoin30_to_bitcoin32_secp256k1_message(&self.tagged_hash().into());
        let signature = ctx.sign_schnorr(&msg, key);
        SignedApiAnnouncement {
            api_announcement: self.clone(),
            signature,
        }
    }
}

impl SignedApiAnnouncement {
    /// Returns true if the signature is valid for the given public key.
    pub fn verify<C: Verification>(
        &self,
        ctx: &secp256k1::Secp256k1<C>,
        pk: &secp256k1::PublicKey,
    ) -> bool {
        let msg: Message = self.api_announcement.tagged_hash().into();
        ctx.verify_schnorr(
            &bitcoin32_to_bitcoin30_schnorr_signature(&self.signature),
            &msg,
            &pk.x_only_public_key().0,
        )
        .is_ok()
    }
}

/// Override api URLs used by the client.
///
/// Takes a list of peer IDs and their API URLs, and overrides the URLs with the
/// ones stored in the respective database. This function is generic so it can
/// be used with both the client and server databases.
pub async fn override_api_urls<P>(
    db: &Database,
    cfg_api_urls: impl IntoIterator<Item = (PeerId, SafeUrl)>,
    db_key_prefix: &P,
    key_to_peer_id: impl Fn(&P::Record) -> PeerId,
) -> BTreeMap<PeerId, SafeUrl>
where
    P: DatabaseLookup + DatabaseKeyPrefix + MaybeSend + MaybeSync,
    P::Record: DatabaseRecord<Value = SignedApiAnnouncement> + DatabaseKey + MaybeSend + MaybeSync,
{
    let mut db_api_urls = db
        .begin_transaction_nc()
        .await
        .find_by_prefix(db_key_prefix)
        .await
        .map(|(key, announcement)| (key_to_peer_id(&key), announcement.api_announcement.api_url))
        .collect::<BTreeMap<_, _>>()
        .await;

    cfg_api_urls
        .into_iter()
        .map(|(peer_id, cfg_api_url)| {
            (peer_id, db_api_urls.remove(&peer_id).unwrap_or(cfg_api_url))
        })
        .collect::<BTreeMap<_, _>>()
}
