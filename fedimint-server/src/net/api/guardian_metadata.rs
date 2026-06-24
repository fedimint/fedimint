use std::time::{Duration, UNIX_EPOCH};

use fedimint_api_client::api::DynGlobalApi;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::net::guardian_metadata::{GuardianMetadata, SignedGuardianMetadata};
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::FmtCompact;
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record, secp256k1};
use fedimint_logging::LOG_NET_API;
use futures::future::join_all;
use futures::stream::StreamExt;
use tokio::select;
use tracing::{debug, info};

use crate::IrohNextApiSettings;
use crate::config::ServerConfig;
use crate::db::DbKeyPrefix;
use crate::net::iroh::derive_iroh_v1_api_secret_key;

fn ensure_iroh_next_remains_available(
    existing_endpoint: Option<&str>,
    configured_endpoint: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(existing_endpoint) = existing_endpoint {
        anyhow::ensure!(
            configured_endpoint == Some(existing_endpoint),
            "Iroh 1.0 API endpoint {existing_endpoint} was previously advertised and must remain \
             enabled unchanged; disabling or rotating it is unsupported"
        );
    }
    Ok(())
}

fn reconcile_iroh_next_endpoint(
    metadata: &mut GuardianMetadata,
    configured_endpoint: Option<String>,
) -> anyhow::Result<bool> {
    ensure_iroh_next_remains_available(
        metadata.iroh_next_endpoint.as_deref(),
        configured_endpoint.as_deref(),
    )?;
    if metadata.iroh_next_endpoint == configured_endpoint {
        return Ok(false);
    }
    metadata.iroh_next_endpoint = configured_endpoint;
    Ok(true)
}

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct GuardianMetadataKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct GuardianMetadataPrefix;

impl_db_record!(
    key = GuardianMetadataKey,
    value = SignedGuardianMetadata,
    db_prefix = DbKeyPrefix::GuardianMetadata,
    notify_on_modify = true,
);
impl_db_lookup!(
    key = GuardianMetadataKey,
    query_prefix = GuardianMetadataPrefix
);

/// Build the federation API client used to publish guardian metadata.
pub async fn prepare_guardian_metadata_service(
    db: &Database,
    cfg: &ServerConfig,
    api_secret: Option<String>,
) -> anyhow::Result<DynGlobalApi> {
    DynGlobalApi::new(
        ConnectorRegistry::build_from_server_env()?.bind().await?,
        super::announcement::get_api_urls(db, &cfg.consensus).await,
        api_secret.as_deref(),
    )
}

/// Store and publish this guardian's current metadata.
pub fn start_guardian_metadata_service(
    db: &Database,
    tg: &TaskGroup,
    cfg: &ServerConfig,
    api_client: DynGlobalApi,
    metadata_updated: bool,
) {
    const INITIAL_DELAY_SECONDS: u64 = 5;
    const FAILURE_RETRY_SECONDS: u64 = 60;
    const SUCCESS_RETRY_SECONDS: u64 = 600;

    let initial_delay = if metadata_updated {
        Duration::ZERO
    } else {
        Duration::from_secs(INITIAL_DELAY_SECONDS)
    };

    let db = db.clone();
    let our_peer_id = cfg.local.identity;
    tg.spawn_cancellable("submit-guardian-metadata", async move {
        // Give other servers some time to start up in case they were just restarted together
        sleep(initial_delay).await;
        loop {
            let mut success = true;
            let metadata_list = db
                .begin_transaction_nc()
                .await
                .find_by_prefix(&GuardianMetadataPrefix)
                .await
                .map(|(peer_key, peer_metadata)| (peer_key.0, peer_metadata))
                .collect::<Vec<(PeerId, SignedGuardianMetadata)>>()
                .await;

            info!(
                target: LOG_NET_API,
                len = %metadata_list.len(),
                "Submitting guardian metadata"
            );
            // Submit all metadata we know (including our own and other peers') to all
            // federation members (in parallel). Each submit_guardian_metadata call
            // broadcasts one piece of metadata to all peers.
            let results = join_all(metadata_list.iter().map(|(peer, metadata)| {
                let api_client = &api_client;
                async move {
                    (*peer, api_client.submit_guardian_metadata(*peer, metadata.clone()).await)
                }
            }))
            .await;

            info!(
                target: LOG_NET_API,
                len = %metadata_list.len(),
                "Done"
            );
            for (peer, result) in results {
                if let Err(err) = result {
                    debug!(target: LOG_NET_API, ?peer, err = %err.fmt_compact(), "Submitting guardian metadata did not succeed for all peers, retrying in {FAILURE_RETRY_SECONDS} seconds");
                    success = false;
                }
            }

            // While we announce all peer metadata, we only want to immediately trigger in case ours changes
            let our_metadata_key = GuardianMetadataKey(our_peer_id);
            let our_metadata = db
                .begin_transaction_nc()
                .await
                .get_value(&our_metadata_key)
                .await
                .expect("Our guardian metadata is always present");

            let new_metadata = db.wait_key_check(&our_metadata_key, |new_metadata| {
                new_metadata.and_then(|new_metadata| {
                    (new_metadata.tagged_hash() != our_metadata.tagged_hash()).then_some(())
                })
            });


            let auto_announcement_delay = if success {
                Duration::from_secs(SUCCESS_RETRY_SECONDS)
            } else if is_running_in_test_env() {
                Duration::from_secs(3)
            } else {
                Duration::from_secs(FAILURE_RETRY_SECONDS)
            };

            select! {
                _ = new_metadata => {},
                () = sleep(auto_announcement_delay) => {},
            }
        }
    });
}

/// Reconciles and signs the server-owned Iroh endpoint in guardian metadata.
///
/// Existing administrator-owned URLs and Pkarr ID are preserved. Returns `true`
/// if metadata was inserted or updated and should be broadcast.
pub async fn reconcile_guardian_metadata(
    db: &Database,
    cfg: &ServerConfig,
    iroh_next_api_settings: Option<&IrohNextApiSettings>,
) -> anyhow::Result<bool> {
    let key = GuardianMetadataKey(cfg.local.identity);
    let mut dbtx = db.begin_transaction().await;
    let existing = dbtx.get_value(&key).await;

    let mut guardian_metadata = existing.as_ref().map_or_else(
        || {
            GuardianMetadata::new(
                cfg.consensus
                    .api_endpoints()
                    .get(&cfg.local.identity)
                    .map(|endpoint| vec![endpoint.url.clone()])
                    .unwrap_or_default(),
                super::pkarr_publish::pkarr_id_z32(&cfg.private.broadcast_secret_key),
                0,
            )
        },
        |existing| existing.guardian_metadata().clone(),
    );

    let iroh_next_endpoint = iroh_next_api_settings.map(|_| {
        derive_iroh_v1_api_secret_key(&cfg.private.broadcast_secret_key)
            .public()
            .to_string()
    });

    let endpoint_changed =
        reconcile_iroh_next_endpoint(&mut guardian_metadata, iroh_next_endpoint)?;
    if existing.is_some() && !endpoint_changed {
        return Ok(false);
    }

    let now = fedimint_core::time::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time should be after UNIX_EPOCH")
        .as_secs();
    guardian_metadata.timestamp_secs = existing.as_ref().map_or(now, |metadata| {
        now.max(
            metadata
                .guardian_metadata()
                .timestamp_secs
                .saturating_add(1),
        )
    });

    let ctx = secp256k1::Secp256k1::new();
    let signed_metadata =
        guardian_metadata.sign(&ctx, &cfg.private.broadcast_secret_key.keypair(&ctx));

    dbtx.insert_entry(&key, &signed_metadata).await;
    dbtx.commit_tx().await;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use fedimint_core::net::guardian_metadata::GuardianMetadata;

    use super::{ensure_iroh_next_remains_available, reconcile_iroh_next_endpoint};

    #[test]
    fn iroh_next_advertisement_is_forward_only() {
        assert!(ensure_iroh_next_remains_available(None, None).is_ok());
        assert!(ensure_iroh_next_remains_available(None, Some("new")).is_ok());
        assert!(ensure_iroh_next_remains_available(Some("existing"), Some("existing")).is_ok());
        assert!(ensure_iroh_next_remains_available(Some("existing"), Some("new")).is_err());
        assert!(ensure_iroh_next_remains_available(Some("existing"), None).is_err());
    }

    #[test]
    fn reconciliation_preserves_administrator_owned_metadata() {
        let api_urls = vec!["wss://guardian.example".parse().expect("valid URL")];
        let mut metadata = GuardianMetadata::new(api_urls.clone(), "pkarr-id".to_owned(), 42);

        assert!(
            reconcile_iroh_next_endpoint(&mut metadata, Some("iroh-id".to_owned()))
                .expect("first advertisement is allowed")
        );
        assert_eq!(metadata.api_urls, api_urls);
        assert_eq!(metadata.pkarr_id_z32, "pkarr-id");
        assert_eq!(metadata.timestamp_secs, 42);
        assert_eq!(metadata.iroh_next_endpoint.as_deref(), Some("iroh-id"));
        assert!(
            !reconcile_iroh_next_endpoint(&mut metadata, Some("iroh-id".to_owned()))
                .expect("unchanged advertisement is allowed")
        );
    }
}
