use std::time::Duration;

use fedimint_core::db::Database;
use fedimint_core::envs::{FM_PKARR_DHT_ENABLE_ENV, FM_PKARR_ENABLE_ENV, is_env_var_set};
use fedimint_core::secp256k1::SecretKey;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::FmtCompact;
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_logging::LOG_NET_API;
use pkarr::SignedPacket;
use tracing::{debug, info, warn};

use crate::config::ServerConfig;

/// Child key index for deriving the pkarr identity from the broadcast secret
const PKARR_IDENTITY_CHILD_ID: ChildId = ChildId(0);

const PUBLISH_INTERVAL_SECS: u64 = 600;
const FAILURE_RETRY_SECS: u64 = 60;
const INITIAL_DELAY_SECS: u64 = 10;
const TXT_RECORD_TTL: u32 = 1800;

/// Derive a pkarr keypair deterministically from the server's broadcast secret
/// key.
///
/// Uses HKDF-based derivation with domain separation to produce an ed25519
/// seed.
pub fn derive_pkarr_keypair(broadcast_sk: &SecretKey) -> pkarr::Keypair {
    let root = DerivableSecret::new_root(&broadcast_sk.secret_bytes(), b"fedimint-pkarr");
    let pkarr_child = root.child_key(PKARR_IDENTITY_CHILD_ID);
    let seed: [u8; 32] = pkarr_child.to_random_bytes();
    pkarr::Keypair::from_secret_key(&seed)
}

/// Get the z-base32 encoded pkarr public key derived from the broadcast secret
/// key.
pub fn pkarr_id_z32(broadcast_sk: &SecretKey) -> String {
    derive_pkarr_keypair(broadcast_sk).to_z32()
}

/// Spawn a background task that periodically publishes this guardian's API
/// URL(s) as pkarr DNS TXT records.
pub async fn start_pkarr_publish_service(
    db: &Database,
    tg: &TaskGroup,
    cfg: &ServerConfig,
) -> anyhow::Result<()> {
    let keypair = derive_pkarr_keypair(&cfg.private.broadcast_secret_key);

    let pkarr_enabled =
        fedimint_core::envs::is_env_var_set_opt(FM_PKARR_ENABLE_ENV).unwrap_or(true);
    let dht_enabled = is_env_var_set(FM_PKARR_DHT_ENABLE_ENV);

    if !pkarr_enabled {
        info!(
            target: LOG_NET_API,
            pkarr_id = %keypair.to_z32(),
            "Pkarr publishing disabled"
        );
        return Ok(());
    }

    let mut builder = pkarr::Client::builder();
    if !dht_enabled {
        builder.no_dht();
    }
    let client = builder.build()?;

    let db = db.clone();
    let our_peer_id = cfg.local.identity;
    let consensus_cfg = cfg.consensus.clone();

    info!(
        target: LOG_NET_API,
        pkarr_id = %keypair.to_z32(),
        dht_enabled,
        "Starting pkarr publish service"
    );

    tg.spawn_cancellable("pkarr-publish", async move {
        sleep(Duration::from_secs(INITIAL_DELAY_SECS)).await;

        loop {
            let api_urls = super::announcement::get_api_urls(&db, &consensus_cfg).await;
            let our_url = api_urls.get(&our_peer_id);

            let success = if let Some(url) = our_url {
                publish_api_url(&client, &keypair, &url.to_string()).await
            } else {
                debug!(
                    target: LOG_NET_API,
                    "No API URL found for our peer, skipping pkarr publish"
                );
                false
            };

            let delay = if success {
                Duration::from_secs(PUBLISH_INTERVAL_SECS)
            } else {
                Duration::from_secs(FAILURE_RETRY_SECS)
            };

            sleep(delay).await;
        }
    });

    Ok(())
}

async fn publish_api_url(client: &pkarr::Client, keypair: &pkarr::Keypair, url: &str) -> bool {
    let signed_packet = match build_signed_packet(keypair, url) {
        Ok(packet) => packet,
        Err(e) => {
            warn!(
                target: LOG_NET_API,
                err = %e.fmt_compact(),
                "Failed to build pkarr signed packet"
            );
            return false;
        }
    };

    match client.publish(&signed_packet, None).await {
        Ok(()) => {
            info!(
                target: LOG_NET_API,
                url,
                pkarr_id = %keypair.to_z32(),
                "Published API URL to pkarr"
            );
            true
        }
        Err(e) => {
            debug!(
                target: LOG_NET_API,
                err = %e.fmt_compact(),
                "Failed to publish to pkarr, will retry"
            );
            false
        }
    }
}

fn build_signed_packet(
    keypair: &pkarr::Keypair,
    url: &str,
) -> Result<SignedPacket, pkarr::errors::SignedPacketBuildError> {
    SignedPacket::builder()
        .txt(
            pkarr::dns::Name::new_unchecked(
                fedimint_core::net::guardian_metadata::PKARR_API_RECORD_NAME,
            ),
            url.try_into().expect("API URL should be valid TXT data"),
            TXT_RECORD_TTL,
        )
        .sign(keypair)
}
