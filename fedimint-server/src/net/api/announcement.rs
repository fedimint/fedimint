use bitcoin::secp256k1;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::net::api_announcement::{ApiAnnouncement, SignedApiAnnouncement};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId};

use crate::config::ServerConfig;
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
