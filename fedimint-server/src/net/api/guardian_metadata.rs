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

use crate::IrohNextSettings;
use crate::config::ServerConfig;
use crate::db::DbKeyPrefix;
use crate::net::broadcast_keys;

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

pub async fn start_guardian_metadata_service(
    db: &Database,
    tg: &TaskGroup,
    cfg: &ServerConfig,
    api_secret: Option<String>,
    iroh_next_settings: Option<&IrohNextSettings>,
) -> anyhow::Result<()> {
    const INITIAL_DELAY_SECONDS: u64 = 5;
    const FAILURE_RETRY_SECONDS: u64 = 60;
    const SUCCESS_RETRY_SECONDS: u64 = 600;

    let initial_delay = if update_signed_guardian_metadata(db, cfg, iroh_next_settings).await {
        Duration::ZERO
    } else {
        Duration::from_secs(INITIAL_DELAY_SECONDS)
    };

    let db = db.clone();
    let api_client = DynGlobalApi::new(
        ConnectorRegistry::build_from_server_env()?.bind().await?,
        super::announcement::get_api_urls(&db, &cfg.consensus).await,
        api_secret.as_deref(),
    )?;

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

    Ok(())
}

/// Builds and signs guardian metadata from the current config,
/// updating the database if the metadata has changed.
///
/// Returns `true` if metadata was inserted/updated (new data to
/// broadcast), `false` if the existing metadata is identical.
async fn update_signed_guardian_metadata(
    db: &Database,
    cfg: &ServerConfig,
    iroh_next_settings: Option<&IrohNextSettings>,
) -> bool {
    let mut guardian_metadata = GuardianMetadata::new(
        cfg.consensus
            .api_endpoints()
            .get(&cfg.local.identity)
            .map(|endpoint| vec![endpoint.url.clone()])
            .unwrap_or_default(),
        super::pkarr_publish::pkarr_id_z32(&cfg.private.broadcast_secret_key),
        fedimint_core::time::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time should be after UNIX_EPOCH")
            .as_secs(),
    );

    if iroh_next_settings.is_some() {
        let iroh_sk = broadcast_keys::derive_iroh_next_api_sk(&cfg.private.broadcast_secret_key);
        guardian_metadata = guardian_metadata.with_iroh_next(
            broadcast_keys::IROH_NEXT_VERSION.to_string(),
            iroh_sk.public().to_string(),
        );
    }
    let ctx = secp256k1::Secp256k1::new();
    let signed_metadata =
        guardian_metadata.sign(&ctx, &cfg.private.broadcast_secret_key.keypair(&ctx));

    let key = GuardianMetadataKey(cfg.local.identity);
    let mut dbtx = db.begin_transaction().await;

    if let Some(existing) = dbtx.get_value(&key).await
        && existing.tagged_hash() == signed_metadata.tagged_hash()
    {
        return false;
    }

    dbtx.insert_entry(&key, &signed_metadata).await;
    dbtx.commit_tx().await;

    true
}
