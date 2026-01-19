use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::config::ClientConfig;
use fedimint_core::db::{
    Database, IReadDatabaseTransactionOpsTyped, IWriteDatabaseTransactionOpsTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::net::api_announcement::{SignedApiAnnouncement, override_api_urls};
use fedimint_core::runtime::{self, sleep};
use fedimint_core::secp256k1::SECP256K1;
use fedimint_core::util::backoff_util::custom_backoff;
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_core::{NumPeersExt as _, PeerId, impl_db_lookup, impl_db_record};
use fedimint_logging::LOG_CLIENT;
use futures::stream::{FuturesUnordered, StreamExt as _};
use tracing::debug;

use crate::Client;
use crate::db::DbKeyPrefix;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ApiAnnouncementKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct ApiAnnouncementPrefix;

impl_db_record!(
    key = ApiAnnouncementKey,
    value = SignedApiAnnouncement,
    db_prefix = DbKeyPrefix::ApiUrlAnnouncement,
    notify_on_modify = false,
);
impl_db_lookup!(
    key = ApiAnnouncementKey,
    query_prefix = ApiAnnouncementPrefix
);

/// Fetches API URL announcements from guardians, validates them and updates the
/// DB if any new more upt to date ones are found.
pub(crate) async fn run_api_announcement_refresh_task(client_inner: Arc<Client>) {
    // Wait for the guardian keys to be available
    let guardian_pub_keys = client_inner.get_guardian_public_keys_blocking().await;
    loop {
        if let Err(err) = {
            let api: &DynGlobalApi = &client_inner.api;
            let results = fetch_api_announcements_from_at_least_num_of_peers(
                1,
                api,
                &guardian_pub_keys,
                if is_running_in_test_env() {
                    Duration::from_millis(1)
                } else {
                    Duration::from_secs(30)
                },
            )
            .await;
            store_api_announcements_updates_from_peers(client_inner.db(), &results).await
        } {
            debug!(target: LOG_CLIENT, err = %err.fmt_compact_anyhow(), "Refreshing api announcements failed");
        }

        let duration = if is_running_in_test_env() {
            Duration::from_secs(1)
        } else {
            // Check once an hour if there are new announcements
            Duration::from_secs(3600)
        };
        sleep(duration).await;
    }
}

pub(crate) async fn store_api_announcements_updates_from_peers(
    db: &Database,
    updates: &[BTreeMap<PeerId, SignedApiAnnouncement>],
) -> Result<(), anyhow::Error> {
    for announcements in updates {
        store_api_announcement_updates(db, announcements).await;
    }

    Ok(())
}

pub(crate) type PeersSignedApiAnnouncements = BTreeMap<PeerId, SignedApiAnnouncement>;

/// Fetch responses from at least `num_responses_required` of peers.
///
/// Will wait a little bit extra in hopes of collecting more than strictly
/// needed responses.
pub(crate) async fn fetch_api_announcements_from_at_least_num_of_peers(
    num_responses_required: usize,
    api: &DynGlobalApi,
    guardian_pub_keys: &BTreeMap<PeerId, bitcoin::secp256k1::PublicKey>,
    extra_response_wait: Duration,
) -> Vec<PeersSignedApiAnnouncements> {
    let num_peers = guardian_pub_keys.to_num_peers();
    // Keep trying, initially somewhat aggressively, but after a while retry very
    // slowly, because chances for response are getting lower and lower.
    let mut backoff = custom_backoff(Duration::from_millis(200), Duration::from_secs(600), None);

    // Make a single request to a peer after a delay
    async fn make_request(
        delay: Duration,
        peer_id: PeerId,
        api: &DynGlobalApi,
        guardian_pub_keys: &BTreeMap<PeerId, bitcoin::secp256k1::PublicKey>,
    ) -> (PeerId, anyhow::Result<PeersSignedApiAnnouncements>) {
        runtime::sleep(delay).await;

        let result = async {
            let announcements = api.api_announcements(peer_id).await.with_context(move || {
                format!("Fetching API announcements from peer {peer_id} failed")
            })?;

            // If any of the announcements is invalid something is fishy with that
            // guardian and we ignore all its responses
            for (peer_id, announcement) in &announcements {
                let Some(guardian_pub_key) = guardian_pub_keys.get(peer_id) else {
                    bail!("Guardian public key not found for peer {}", peer_id);
                };

                if !announcement.verify(SECP256K1, guardian_pub_key) {
                    bail!("Failed to verify announcement for peer {}", peer_id);
                }
            }
            Ok(announcements)
        }
        .await;

        (peer_id, result)
    }

    let mut requests = FuturesUnordered::new();

    for peer_id in num_peers.peer_ids() {
        requests.push(make_request(
            Duration::ZERO,
            peer_id,
            api,
            guardian_pub_keys,
        ));
    }

    let mut responses = Vec::new();

    loop {
        let next_response = if responses.len() < num_responses_required {
            // If we don't have enough responses yet, we wait
            requests.next().await
        } else {
            // if we do have responses we need, we wait opportunistically just for a small
            // duration if any other responses are ready anyway, just to not
            // throw them away
            fedimint_core::runtime::timeout(extra_response_wait, requests.next())
                .await
                .ok()
                .flatten()
        };

        let Some((peer_id, response)) = next_response else {
            break;
        };

        match response {
            Err(err) => {
                debug!(
                    target: LOG_CLIENT,
                    %peer_id,
                    err = %err.fmt_compact_anyhow(),
                    "Failed to fetch API announcements from peer"
                );
                requests.push(make_request(
                    backoff.next().expect("Keeps retrying"),
                    peer_id,
                    api,
                    guardian_pub_keys,
                ));
            }
            Ok(announcements) => {
                responses.push(announcements);
            }
        }
    }

    responses
}

pub(crate) async fn store_api_announcement_updates(
    db: &Database,
    announcements: &BTreeMap<PeerId, SignedApiAnnouncement>,
) {
    let mut dbtx = db.begin_write_transaction().await;

    for (peer, new_announcement) in announcements {
        let replace_current_announcement = dbtx
            .get_value(&ApiAnnouncementKey(*peer))
            .await
            .is_none_or(|current_announcement| {
                current_announcement.api_announcement.nonce
                    < new_announcement.api_announcement.nonce
            });
        if replace_current_announcement {
            debug!(target: LOG_CLIENT, ?peer, %new_announcement.api_announcement.api_url, "Updating API announcement");
            dbtx.insert_entry(&ApiAnnouncementKey(*peer), new_announcement)
                .await;
        }
    }

    dbtx.commit_tx().await;
}

/// Returns a list of all peers and their respective API URLs taking into
/// account announcements overwriting the URLs contained in the original
/// configuration.
pub async fn get_api_urls(db: &Database, cfg: &ClientConfig) -> BTreeMap<PeerId, SafeUrl> {
    override_api_urls(
        db,
        cfg.global
            .api_endpoints
            .iter()
            .map(|(peer_id, peer_url)| (*peer_id, peer_url.url.clone())),
        &ApiAnnouncementPrefix,
        |key| key.0,
    )
    .await
}
