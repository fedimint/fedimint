use std::collections::BTreeMap;

use bitcoin::secp256k1;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::net::api_announcement::{
    override_api_urls, ApiAnnouncement, SignedApiAnnouncement,
};
use fedimint_core::util::SafeUrl;
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId};

use crate::config::{ServerConfig, ServerConfigConsensus};
use crate::consensus::db::DbKeyPrefix;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ApiAnnouncementKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ApiAnnouncementPrefix;

impl_db_record!(
    key = ApiAnnouncementKey,
    value = SignedApiAnnouncement,
    db_prefix = DbKeyPrefix::ApiAnnouncements,
    notify_on_modify = false,
);
impl_db_lookup!(
    key = ApiAnnouncementKey,
    query_prefix = ApiAnnouncementPrefix
);

/// Checks if we already have a signed API endpoint announcement for our own
/// identity in the database and creates one if not.
pub async fn sign_api_announcement_if_not_present(db: &Database, cfg: &ServerConfig) {
    let mut dbtx = db.begin_transaction().await;
    if dbtx
        .get_value(&ApiAnnouncementKey(cfg.local.identity))
        .await
        .is_some()
    {
        return;
    }

    let api_announcement = ApiAnnouncement::new(
        cfg.consensus.api_endpoints[&cfg.local.identity].url.clone(),
        0,
    );
    let ctx = secp256k1::Secp256k1::new();
    let signed_announcement =
        api_announcement.sign(&ctx, &cfg.private.broadcast_secret_key.keypair(&ctx));

    dbtx.insert_entry(
        &ApiAnnouncementKey(cfg.local.identity),
        &signed_announcement,
    )
    .await;
    dbtx.commit_tx().await;
}

/// Returns a list of all peers and their respective API URLs taking into
/// account announcements overwriting the URLs contained in the original
/// configuration.
pub async fn get_api_urls(db: &Database, cfg: &ServerConfigConsensus) -> BTreeMap<PeerId, SafeUrl> {
    override_api_urls(
        db,
        cfg.api_endpoints
            .iter()
            .map(|(peer_id, peer_url)| (*peer_id, peer_url.url.clone())),
        &ApiAnnouncementPrefix,
        |key| key.0,
    )
    .await
}
