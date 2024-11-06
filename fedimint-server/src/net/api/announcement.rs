use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_api_client::api::net::Connector;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::bitcoin_migration::bitcoin30_to_bitcoin32_secp256k1_secret_key;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::net::api_announcement::{
    override_api_urls, ApiAnnouncement, SignedApiAnnouncement,
};
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::util::SafeUrl;
use fedimint_core::{impl_db_lookup, impl_db_record, secp256k1, PeerId};
use tokio::select;
use tracing::debug;

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
    notify_on_modify = true,
);
impl_db_lookup!(
    key = ApiAnnouncementKey,
    query_prefix = ApiAnnouncementPrefix
);

pub async fn start_api_announcement_service(
    db: &Database,
    tg: &TaskGroup,
    cfg: &ServerConfig,
    api_secret: Option<String>,
) {
    const INITIAL_DEALY_SECONDS: u64 = 5;
    const FAILURE_RETRY_SECONDS: u64 = 60;
    const SUCCESS_RETRY_SECONDS: u64 = 600;

    insert_signed_api_announcement_if_not_present(db, cfg).await;

    let db = db.clone();
    // FIXME: (@leonardo) how should we handle the connector here ?
    let api_client = DynGlobalApi::from_endpoints(
        get_api_urls(&db, &cfg.consensus).await,
        &api_secret,
        &Connector::default(),
    );
    let our_peer_id = cfg.local.identity;
    tg.spawn_cancellable("submit-api-url-announcement", async move {
        // Give other servers some time to start up in case they were just restarted
        // together
        sleep(Duration::from_secs(INITIAL_DEALY_SECONDS)).await;
        loop {
            let announcement = db.begin_transaction_nc()
                .await
                .get_value(&ApiAnnouncementKey(our_peer_id))
                .await
                .expect("Our own API announcement should be present in the database");

            if let Err(e) = api_client
                .submit_api_announcement(our_peer_id, announcement.clone())
                .await
            {
                debug!(?e, "Announcing our API URL did not succeed for all peers, retrying in {FAILURE_RETRY_SECONDS} seconds");
                sleep(Duration::from_secs(FAILURE_RETRY_SECONDS)).await;
            } else {
                let our_announcement_key = ApiAnnouncementKey(our_peer_id);
                let new_announcement = db.wait_key_check(
                    &our_announcement_key,
                    |new_announcement| {
                        new_announcement.and_then(
                            |new_announcement| (new_announcement.api_announcement.nonce != announcement.api_announcement.nonce).then_some(())
                        )
                    });

                select! {
                    _ = new_announcement => {},
                    () = sleep(Duration::from_secs(SUCCESS_RETRY_SECONDS)) => {},
                }
            }
        }
    });
}

/// Checks if we already have a signed API endpoint announcement for our own
/// identity in the database and creates one if not.
async fn insert_signed_api_announcement_if_not_present(db: &Database, cfg: &ServerConfig) {
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
    let signed_announcement = api_announcement.sign(
        &ctx,
        &bitcoin30_to_bitcoin32_secp256k1_secret_key(&cfg.private.broadcast_secret_key)
            .keypair(&ctx),
    );

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
