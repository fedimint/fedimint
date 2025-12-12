use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::net::guardian_metadata::SignedGuardianMetadata;
use fedimint_core::runtime::{self, sleep};
use fedimint_core::secp256k1::SECP256K1;
use fedimint_core::util::backoff_util::custom_backoff;
use fedimint_core::util::{FmtCompact as _, FmtCompactAnyhow as _};
use fedimint_core::{NumPeersExt as _, PeerId, impl_db_lookup, impl_db_record};
use fedimint_logging::LOG_CLIENT;
use futures::stream::{FuturesUnordered, StreamExt as _};
use tracing::debug;

use crate::Client;
use crate::db::DbKeyPrefix;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct GuardianMetadataKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct GuardianMetadataPrefix;

impl_db_record!(
    key = GuardianMetadataKey,
    value = SignedGuardianMetadata,
    db_prefix = DbKeyPrefix::GuardianMetadata,
    notify_on_modify = false,
);
impl_db_lookup!(
    key = GuardianMetadataKey,
    query_prefix = GuardianMetadataPrefix
);

/// Fetches guardian metadata from guardians, validates them and updates the
/// DB if any new more up to date ones are found.
pub(crate) async fn run_guardian_metadata_refresh_task(client_inner: Arc<Client>) {
    // Wait for the guardian keys to be available
    let guardian_pub_keys = client_inner.get_guardian_public_keys_blocking().await;
    loop {
        if let Err(err) = {
            let api: &DynGlobalApi = &client_inner.api;
            let results = fetch_guardian_metadata_from_at_least_num_of_peers(
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
            store_guardian_metadata_updates_from_peers(
                client_inner.db(),
                &guardian_pub_keys,
                &results,
            )
            .await
        } {
            debug!(target: LOG_CLIENT, err = %err.fmt_compact_anyhow(), "Refreshing guardian metadata failed");
        }

        let duration = if is_running_in_test_env() {
            Duration::from_secs(1)
        } else {
            // Check once an hour if there are new metadata
            Duration::from_secs(3600)
        };
        sleep(duration).await;
    }
}

pub(crate) async fn store_guardian_metadata_updates_from_peers(
    db: &Database,
    guardian_pub_keys: &BTreeMap<PeerId, bitcoin::secp256k1::PublicKey>,
    updates: &[BTreeMap<PeerId, SignedGuardianMetadata>],
) -> Result<(), anyhow::Error> {
    for metadata_map in updates {
        store_guardian_metadata_updates(db, guardian_pub_keys, metadata_map).await;
    }

    Ok(())
}

pub(crate) type PeersSignedGuardianMetadata = BTreeMap<PeerId, SignedGuardianMetadata>;

/// Fetch responses from at least `num_responses_required` of peers.
///
/// Will wait a little bit extra in hopes of collecting more than strictly
/// needed responses.
pub(crate) async fn fetch_guardian_metadata_from_at_least_num_of_peers(
    num_responses_required: usize,
    api: &DynGlobalApi,
    guardian_pub_keys: &BTreeMap<PeerId, bitcoin::secp256k1::PublicKey>,
    extra_response_wait: Duration,
) -> Vec<PeersSignedGuardianMetadata> {
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
    ) -> (PeerId, anyhow::Result<PeersSignedGuardianMetadata>) {
        runtime::sleep(delay).await;

        let result = async {
            let metadata_map = api.guardian_metadata(peer_id).await.with_context(move || {
                format!("Fetching guardian metadata from peer {peer_id} failed")
            })?;

            // If any of the metadata is invalid something is fishy with that
            // guardian and we ignore all its responses
            for (peer_id, metadata) in &metadata_map {
                let Some(guardian_pub_key) = guardian_pub_keys.get(peer_id) else {
                    bail!("Guardian public key not found for peer {}", peer_id);
                };

                let now = fedimint_core::time::duration_since_epoch();
                if let Err(e) = metadata.verify(SECP256K1, guardian_pub_key, now) {
                    bail!("Failed to verify metadata for peer {}: {}", peer_id, e);
                }
            }
            Ok(metadata_map)
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
                    "Failed to fetch guardian metadata from peer"
                );
                requests.push(make_request(
                    backoff.next().expect("Keeps retrying"),
                    peer_id,
                    api,
                    guardian_pub_keys,
                ));
            }
            Ok(metadata) => {
                responses.push(metadata);
            }
        }
    }

    responses
}

pub(crate) async fn store_guardian_metadata_updates(
    db: &Database,
    guardian_pub_keys: &BTreeMap<PeerId, bitcoin::secp256k1::PublicKey>,
    metadata_map: &BTreeMap<PeerId, SignedGuardianMetadata>,
) {
    let now = fedimint_core::time::duration_since_epoch();

    db.autocommit(
        |dbtx, _| {
            let metadata_map_inner = metadata_map.clone();
            let guardian_pub_keys_inner = guardian_pub_keys.clone();
            Box::pin(async move {
                for (peer, new_metadata) in metadata_map_inner {
                    // Verify signature before storing
                    let Some(guardian_pub_key) = guardian_pub_keys_inner.get(&peer) else {
                        debug!(
                            target: LOG_CLIENT,
                            ?peer,
                            "Skipping metadata update: guardian public key not found"
                        );
                        continue;
                    };

                    if let Err(e) = new_metadata.verify(SECP256K1, guardian_pub_key, now) {
                        debug!(
                            target: LOG_CLIENT,
                            ?peer,
                            err = %e.fmt_compact(),
                            "Skipping metadata update: verification failed"
                        );
                        continue;
                    }

                    let replace_current_metadata = dbtx
                        .get_value(&GuardianMetadataKey(peer))
                        .await
                        .is_none_or(|current_metadata| {
                            // Replace if new metadata has a newer timestamp
                            current_metadata.guardian_metadata().timestamp_secs
                                < new_metadata.guardian_metadata().timestamp_secs
                        });
                    if replace_current_metadata {
                        debug!(target: LOG_CLIENT, ?peer, "Updating guardian metadata");
                        dbtx.insert_entry(&GuardianMetadataKey(peer), &new_metadata)
                            .await;
                    }
                }

                Result::<(), ()>::Ok(())
            })
        },
        None,
    )
    .await
    .expect("Will never return an error");
}
