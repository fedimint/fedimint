use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_api_client::api::DynGlobalApi;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::{
    Database, IReadDatabaseTransactionOpsTyped, IWriteDatabaseTransactionOpsTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::net::api_announcement::{
    ApiAnnouncement, SignedApiAnnouncement, override_api_urls,
};
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record, secp256k1};
use fedimint_logging::LOG_NET_API;
use futures::stream::StreamExt;
use tokio::select;
use tracing::debug;

use crate::config::{ServerConfig, ServerConfigConsensus};
use crate::db::DbKeyPrefix;

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
) -> anyhow::Result<()> {
    const INITIAL_DEALY_SECONDS: u64 = 5;
    const FAILURE_RETRY_SECONDS: u64 = 60;
    const SUCCESS_RETRY_SECONDS: u64 = 600;

    insert_signed_api_announcement_if_not_present(db, cfg).await;

    let db = db.clone();
    // FIXME: (@leonardo) how should we handle the connector here ?
    let api_client = DynGlobalApi::new(
        // TODO: get from somewhere/unify?
        ConnectorRegistry::build_from_server_env()?.bind().await?,
        get_api_urls(&db, &cfg.consensus).await,
        api_secret.as_deref(),
    )?;

    let our_peer_id = cfg.local.identity;
    tg.spawn_cancellable("submit-api-url-announcement", async move {
        // Give other servers some time to start up in case they were just restarted
        // together
        sleep(Duration::from_secs(INITIAL_DEALY_SECONDS)).await;
        loop {
            let mut success = true;
            let announcements = db.begin_read_transaction()
                .await
                .find_by_prefix(&ApiAnnouncementPrefix)
                .await
                .map(|(peer_key, peer_announcement)| (peer_key.0, peer_announcement))
                .collect::<Vec<(PeerId, SignedApiAnnouncement)>>()
                .await;

            // Announce all peer API URLs we know, but at least our own
            for (peer, announcement) in announcements {
                if let Err(err) = api_client
                    .submit_api_announcement(peer, announcement.clone())
                    .await {
                    debug!(target: LOG_NET_API, ?peer, err = %err.fmt_compact(), "Announcing API URL did not succeed for all peers, retrying in {FAILURE_RETRY_SECONDS} seconds");
                    success = false;
                }
            }

            // While we announce all peer API urls, we only want to immediately trigger in case
            let our_announcement_key = ApiAnnouncementKey(our_peer_id);
            let our_announcement = db
                .begin_read_transaction()
                .await
                .get_value(&our_announcement_key)
                .await
                .expect("Our announcement is always present");
            let new_announcement = db.wait_key_check(
                &our_announcement_key,
                |new_announcement| {
                    new_announcement.and_then(
                        |new_announcement| (new_announcement.api_announcement.nonce != our_announcement.api_announcement.nonce).then_some(())
                    )
                });

            let auto_announcement_delay = if success {
                Duration::from_secs(SUCCESS_RETRY_SECONDS)
            } else {
                Duration::from_secs(FAILURE_RETRY_SECONDS)
            };

            select! {
                _ = new_announcement => {},
                () = sleep(auto_announcement_delay) => {},
            }
        }
    });

    Ok(())
}

/// Checks if we already have a signed API endpoint announcement for our own
/// identity in the database and creates one if not.
async fn insert_signed_api_announcement_if_not_present(db: &Database, cfg: &ServerConfig) {
    let mut dbtx = db.begin_write_transaction().await;
    if dbtx
        .get_value(&ApiAnnouncementKey(cfg.local.identity))
        .await
        .is_some()
    {
        return;
    }

    let api_announcement = ApiAnnouncement::new(
        cfg.consensus.api_endpoints()[&cfg.local.identity]
            .url
            .clone(),
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
        cfg.api_endpoints()
            .iter()
            .map(|(peer_id, peer_url)| (*peer_id, peer_url.url.clone())),
        &ApiAnnouncementPrefix,
        |key| key.0,
    )
    .await
}
