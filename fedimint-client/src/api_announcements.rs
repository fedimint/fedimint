use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use fedimint_core::config::ClientConfig;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::net::api_announcement::{override_api_urls, SignedApiAnnouncement};
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::SECP256K1;
use fedimint_core::util::{backoff_util, retry, SafeUrl};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId};
use fedimint_logging::LOG_CLIENT;
use futures::future::join_all;
use tracing::{info, warn};

use crate::db::DbKeyPrefix;
use crate::Client;

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
pub async fn run_api_announcement_sync(client_inner: Arc<Client>) {
    // Wait for the guardian keys to be available
    let guardian_pub_keys = client_inner.get_guardian_public_keys_blocking().await;
    loop {
        let results = join_all(client_inner.api.all_peers().iter()
            .map(|peer_id| async {
                let peer_id = *peer_id;
                let announcements =

                retry(
                    "Fetch api announcement (sync)",
                    backoff_util::aggressive_backoff(),
                    || async {
                        client_inner
                            .api
                            .api_announcements(peer_id)
                            .await
                            .with_context(move || format!("Fetching API announcements from peer {peer_id} failed"))
                    },
                )
                .await?;

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

                client_inner
                    .db
                    .autocommit(
                        |dbtx, _|{
                            let announcements_inner = announcements.clone();
                        Box::pin(async move {
                            for (peer, new_announcement) in announcements_inner {
                                let replace_current_announcement = dbtx
                                    .get_value(&ApiAnnouncementKey(peer))
                                    .await
                                    .map_or(true, |current_announcement| {
                                        current_announcement.api_announcement.nonce
                                            < new_announcement.api_announcement.nonce
                                    });
                                if replace_current_announcement {
                                    info!(target: LOG_CLIENT, ?peer, %new_announcement.api_announcement.api_url, "Updating API announcement");
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

                Ok(())
            })).await;

        for (peer_id, result) in guardian_pub_keys.keys().zip(results) {
            if let Err(e) = result {
                warn!(target: LOG_CLIENT, %peer_id, ?e, "Failed to process API announcements");
            }
        }

        // Check once an hour if there are new announcements
        sleep(Duration::from_secs(3600)).await;
    }
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
