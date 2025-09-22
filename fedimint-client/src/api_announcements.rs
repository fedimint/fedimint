use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::config::ClientConfig;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::net::api_announcement::{SignedApiAnnouncement, override_api_urls};
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::SECP256K1;
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_logging::LOG_CLIENT;
use futures::future::join_all;
use tracing::{debug, warn};

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
pub(crate) async fn run_api_announcement_sync(client_inner: Arc<Client>) {
    // Wait for the guardian keys to be available
    let guardian_pub_keys = client_inner.get_guardian_public_keys_blocking().await;
    loop {
        if let Err(err) =
            refresh_api_announcement_sync(&client_inner.api, client_inner.db(), &guardian_pub_keys)
                .await
        {
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

pub(crate) async fn refresh_api_announcement_sync(
    api: &DynGlobalApi,
    db: &Database,
    guardian_pub_keys: &BTreeMap<PeerId, bitcoin::secp256k1::PublicKey>,
) -> anyhow::Result<()> {
    let results = fetch_api_announcements_from_all_peers(api, guardian_pub_keys).await;

    let mut some_success = false;

    for (peer_id, result) in guardian_pub_keys.keys().zip(results) {
        match result {
            Ok(announcements) => {
                store_api_announcements(db, announcements).await;
                some_success |= true
            }
            Err(e) => {
                warn!(target: LOG_CLIENT, %peer_id, err = %e.fmt_compact_anyhow(), "Failed to process API announcements");
            }
        }
    }

    if some_success {
        Ok(())
    } else {
        bail!("Unable to get any api announcements");
    }
}

async fn fetch_api_announcements_from_all_peers(
    api: &DynGlobalApi,
    guardian_pub_keys: &BTreeMap<PeerId, bitcoin::secp256k1::PublicKey>,
) -> Vec<Result<BTreeMap<PeerId, SignedApiAnnouncement>, anyhow::Error>> {
    join_all(api.all_peers().iter().map(|peer_id| async {
        let peer_id = *peer_id;
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
    }))
    .await
}

pub(crate) async fn store_api_announcements(
    db: &Database,
    announcements: BTreeMap<PeerId, SignedApiAnnouncement>,
) {
    db
        .autocommit(
            |dbtx, _|{
                let announcements_inner = announcements.clone();
            Box::pin(async move {
                for (peer, new_announcement) in announcements_inner {
                    let replace_current_announcement = dbtx
                        .get_value(&ApiAnnouncementKey(peer))
                        .await.is_none_or(|current_announcement| {
                            current_announcement.api_announcement.nonce
                                < new_announcement.api_announcement.nonce
                        });
                    if replace_current_announcement {
                        debug!(target: LOG_CLIENT, ?peer, %new_announcement.api_announcement.api_url, "Updating API announcement");
                        dbtx.insert_entry(&ApiAnnouncementKey(peer), &new_announcement)
                            .await;
                    }
                }

                Result::<(), ()>::Ok(())
            })},
            None,
        )
        .await
        .expect("Will never return an error");
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
