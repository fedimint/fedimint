use std::collections::BTreeMap;

use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::PeerId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::envs::{FM_PKARR_DHT_ENABLE_ENV, FM_PKARR_ENABLE_ENV, is_env_var_set};
use fedimint_core::net::guardian_metadata::SignedGuardianMetadata;
use fedimint_core::util::{FmtCompact as _, FmtCompactAnyhow as _, SafeUrl};
use fedimint_logging::LOG_CLIENT;
use futures::stream::StreamExt as _;
use pkarr::dns::rdata::RData;
use tracing::{debug, warn};

use super::{
    GuardianMetadataPrefix, PeersSignedGuardianMetadata,
    fetch_guardian_metadata_from_at_least_num_of_peers,
};
use crate::Client;

/// Resolve guardian API URLs via Pkarr network using cached `pkarr_id_z32`
/// from locally stored guardian metadata.
///
/// Respects the same env vars as the server-side publisher:
/// - `FM_PKARR_ENABLE` (default: enabled) — master switch for pkarr
/// - `FM_PKARR_DHT_ENABLE` (default: disabled) — also use Mainline DHT
///   (requires the `pkarr-dht` compile-time feature)
async fn resolve_api_urls_via_pkarr(db: &Database) -> BTreeMap<PeerId, SafeUrl> {
    let pkarr_enabled =
        fedimint_core::envs::is_env_var_set_opt(FM_PKARR_ENABLE_ENV).unwrap_or(true);

    if !pkarr_enabled {
        debug!(
            target: LOG_CLIENT,
            "Pkarr resolve disabled"
        );
        return BTreeMap::new();
    }

    // DHT requires both the compile-time feature and the runtime env var
    let dht_enabled = cfg!(feature = "pkarr-dht") && is_env_var_set(FM_PKARR_DHT_ENABLE_ENV);

    let mut dbtx = db.begin_transaction_nc().await;
    let cached_metadata: BTreeMap<PeerId, SignedGuardianMetadata> = dbtx
        .find_by_prefix(&GuardianMetadataPrefix)
        .await
        .map(|(key, metadata)| (key.0, metadata))
        .collect()
        .await;
    drop(dbtx);

    let mut builder = pkarr::Client::builder();
    if !dht_enabled {
        builder.no_dht();
    }
    let pkarr_client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            debug!(
                target: LOG_CLIENT,
                err = %e.fmt_compact(),
                "Failed to build pkarr client"
            );
            return BTreeMap::new();
        }
    };

    let resolve_futures: Vec<_> = cached_metadata
        .iter()
        .filter_map(|(peer_id, meta)| {
            let pkarr_id = meta.guardian_metadata().pkarr_id_z32.clone();
            if pkarr_id.is_empty() {
                return None;
            }
            let client = &pkarr_client;
            let peer_id = *peer_id;
            Some(async move {
                let pk = match pkarr::PublicKey::try_from(pkarr_id.as_str()) {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!(
                            target: LOG_CLIENT,
                            %peer_id,
                            err = %e.fmt_compact(),
                            "Failed to parse pkarr public key"
                        );
                        return None;
                    }
                };

                let signed_packet = match client.resolve(&pk).await {
                    Some(sp) => sp,
                    None => {
                        warn!(
                            target: LOG_CLIENT,
                            %peer_id,
                            "No pkarr record found"
                        );
                        return None;
                    }
                };

                for record in signed_packet
                    .resource_records(fedimint_core::net::guardian_metadata::PKARR_API_RECORD_NAME)
                {
                    if let RData::TXT(txt) = &record.rdata
                        && let Ok(url_str) = String::try_from(txt.clone())
                        && let Ok(url) = url_str.parse()
                    {
                        return Some((peer_id, url));
                    }
                }

                warn!(
                    target: LOG_CLIENT,
                    %peer_id,
                    "No fedimint_api TXT record in pkarr response"
                );
                None
            })
        })
        .collect();

    futures::future::join_all(resolve_futures)
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// If no guardians were reachable via normal API, try resolving their
/// current URLs from the Pkarr network and retry the metadata fetch.
pub(crate) async fn try_pkarr_fallback(
    client_inner: &Client,
    guardian_pub_keys: &BTreeMap<PeerId, bitcoin::secp256k1::PublicKey>,
) -> Vec<PeersSignedGuardianMetadata> {
    debug!(
        target: LOG_CLIENT,
        "Normal API unreachable, trying pkarr fallback"
    );

    let pkarr_urls = resolve_api_urls_via_pkarr(client_inner.db()).await;
    if pkarr_urls.is_empty() {
        return vec![];
    }

    let pkarr_api = match DynGlobalApi::new(
        client_inner.endpoints().clone(),
        pkarr_urls,
        client_inner.api_secret().as_deref(),
    ) {
        Ok(api) => api,
        Err(e) => {
            debug!(
                target: LOG_CLIENT,
                err = %e.fmt_compact_anyhow(),
                "Failed to build pkarr fallback API client"
            );
            return vec![];
        }
    };

    fetch_guardian_metadata_from_at_least_num_of_peers(
        1,
        &pkarr_api,
        guardian_pub_keys,
        super::extra_response_wait(),
    )
    .await
}
