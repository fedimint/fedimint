use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_api_client::api::DynGlobalApi;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::net::api_announcement::{ApiAnnouncement, SignedApiAnnouncement};
use fedimint_core::net::guardian_metadata::SignedGuardianMetadata;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record, secp256k1};
use fedimint_logging::LOG_NET_API;
use futures::future::join_all;
use futures::stream::StreamExt;
use tokio::select;
use tracing::debug;

use super::guardian_metadata::GuardianMetadataPrefix;
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

    let initial_delay = if insert_signed_api_announcement_if_not_present(db, cfg).await {
        Duration::ZERO
    } else {
        Duration::from_secs(INITIAL_DEALY_SECONDS)
    };

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
        sleep(initial_delay).await;
        loop {
            let mut success = true;
            let announcements = db.begin_transaction_nc()
                .await
                .find_by_prefix(&ApiAnnouncementPrefix)
                .await
                .map(|(peer_key, peer_announcement)| (peer_key.0, peer_announcement))
                .collect::<Vec<(PeerId, SignedApiAnnouncement)>>()
                .await;

            // Submit all API announcements we know (including our own and other peers')
            // to all federation members (in parallel). Each submit_api_announcement call
            // broadcasts one announcement to all peers.
            let results = join_all(announcements.iter().map(|(peer, announcement)| {
                let api_client = &api_client;
                async move {
                    (*peer, api_client.submit_api_announcement(*peer, announcement.clone()).await)
                }
            }))
            .await;

            for (peer, result) in results {
                if let Err(err) = result {
                    debug!(target: LOG_NET_API, ?peer, err = %err.fmt_compact(), "Announcing API URL did not succeed for all peers, retrying in {FAILURE_RETRY_SECONDS} seconds");
                    success = false;
                }
            }

            // While we announce all peer API urls, we only want to immediately trigger in case
            let our_announcement_key = ApiAnnouncementKey(our_peer_id);
            let our_announcement = db
                .begin_transaction_nc()
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
            } else if is_running_in_test_env() {
                Duration::from_secs(3)
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
///
/// Return `true` fresh announcements were inserted because it was not present
async fn insert_signed_api_announcement_if_not_present(db: &Database, cfg: &ServerConfig) -> bool {
    let mut dbtx = db.begin_transaction().await;
    if dbtx
        .get_value(&ApiAnnouncementKey(cfg.local.identity))
        .await
        .is_some()
    {
        return false;
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

    true
}

/// Returns a list of all peers and their respective API URLs taking into
/// account guardian metadata and API announcements overwriting the URLs
/// contained in the original configuration.
///
/// Priority order:
/// 1. Guardian metadata (if available) - uses first URL from api_urls
/// 2. API announcement (if available)
/// 3. Configured URL (fallback)
pub async fn get_api_urls(db: &Database, cfg: &ServerConfigConsensus) -> BTreeMap<PeerId, SafeUrl> {
    let mut dbtx = db.begin_transaction_nc().await;

    // Load guardian metadata for all peers
    let guardian_metadata: BTreeMap<PeerId, SignedGuardianMetadata> = dbtx
        .find_by_prefix(&GuardianMetadataPrefix)
        .await
        .map(|(key, metadata)| (key.0, metadata))
        .collect()
        .await;

    // Load API announcements for all peers
    let api_announcements: BTreeMap<PeerId, SignedApiAnnouncement> = dbtx
        .find_by_prefix(&ApiAnnouncementPrefix)
        .await
        .map(|(key, announcement)| (key.0, announcement))
        .collect()
        .await;

    // For each peer: prefer guardian metadata, then API announcement, then config
    cfg.api_endpoints()
        .iter()
        .map(|(peer_id, peer_url)| {
            let url = guardian_metadata
                .get(peer_id)
                .and_then(|m| m.guardian_metadata().api_urls.first().cloned())
                .or_else(|| {
                    api_announcements
                        .get(peer_id)
                        .map(|a| a.api_announcement.api_url.clone())
                })
                .unwrap_or_else(|| peer_url.url.clone());
            (*peer_id, url)
        })
        .collect()
}
