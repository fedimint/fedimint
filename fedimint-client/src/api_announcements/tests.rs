use std::collections::BTreeMap;

use fedimint_core::config::{ClientConfig, GlobalClientConfig, PeerUrl};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::CORE_CONSENSUS_VERSION;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::net::guardian_metadata::GuardianMetadata;
use fedimint_core::secp256k1::rand;
use fedimint_core::util::SafeUrl;
use fedimint_core::{PeerId, secp256k1};
use serde::Deserialize;

use super::get_api_urls;
use crate::guardian_metadata::GuardianMetadataKey;

const STABLE_ENDPOINT_ID: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const NEXT_ENDPOINT_ID: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

fn test_config(peer_id: PeerId, url: SafeUrl) -> ClientConfig {
    ClientConfig {
        global: GlobalClientConfig {
            api_endpoints: BTreeMap::from([(
                peer_id,
                PeerUrl {
                    url,
                    name: "peer".to_owned(),
                },
            )]),
            broadcast_public_keys: None,
            consensus_version: CORE_CONSENSUS_VERSION,
            meta: BTreeMap::new(),
        },
        modules: BTreeMap::new(),
    }
}

async fn insert_guardian_metadata(
    db: &Database,
    peer_id: PeerId,
    api_url: SafeUrl,
    endpoint: Option<&str>,
) {
    let ctx = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::new(&ctx, &mut rand::thread_rng());
    let mut metadata = GuardianMetadata::new(vec![api_url], "pkarr-id".to_owned(), 1);
    metadata.iroh_next_endpoint = endpoint.map(str::to_owned);

    let signed = metadata.sign(&ctx, &keypair);
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&GuardianMetadataKey(peer_id), &signed)
        .await;
    dbtx.commit_tx().await;
}

#[tokio::test]
async fn advertised_iroh_next_endpoint_rewrites_iroh_url_to_metadata_endpoint() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let peer_id = PeerId::from(0);
    let stable_url = SafeUrl::parse(&format!("iroh://{STABLE_ENDPOINT_ID}")).expect("valid URL");
    let next_endpoint = NEXT_ENDPOINT_ID;
    insert_guardian_metadata(&db, peer_id, stable_url.clone(), Some(next_endpoint)).await;

    let urls = get_api_urls(&db, &test_config(peer_id, stable_url), true).await;

    assert_eq!(
        urls.get(&peer_id),
        Some(&SafeUrl::parse(&format!("iroh://{next_endpoint}/v1")).expect("valid URL"))
    );
}

#[tokio::test]
async fn missing_endpoint_or_disabled_iroh_next_does_not_rewrite_iroh_url() {
    let stable_url = SafeUrl::parse(&format!("iroh://{STABLE_ENDPOINT_ID}")).expect("valid URL");
    let peer_id = PeerId::from(0);

    for (advertised_endpoint, client_iroh_next_enabled) in
        [(None, true), (Some(NEXT_ENDPOINT_ID), false)]
    {
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        insert_guardian_metadata(&db, peer_id, stable_url.clone(), advertised_endpoint).await;

        let urls = get_api_urls(
            &db,
            &test_config(peer_id, stable_url.clone()),
            client_iroh_next_enabled,
        )
        .await;

        assert_eq!(urls.get(&peer_id), Some(&stable_url));
    }
}

#[tokio::test]
async fn non_iroh_url_is_not_rewritten_to_advertised_iroh_next_endpoint() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let peer_id = PeerId::from(0);
    let stable_url = SafeUrl::parse("wss://example.com/ws/").expect("valid URL");
    insert_guardian_metadata(&db, peer_id, stable_url.clone(), Some(NEXT_ENDPOINT_ID)).await;

    let urls = get_api_urls(&db, &test_config(peer_id, stable_url.clone()), true).await;

    assert_eq!(urls.get(&peer_id), Some(&stable_url));
}

#[tokio::test]
async fn malformed_advertised_iroh_next_endpoint_does_not_fall_back() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let peer_id = PeerId::from(0);
    let stable_url = SafeUrl::parse(&format!("iroh://{STABLE_ENDPOINT_ID}")).expect("valid URL");
    insert_guardian_metadata(&db, peer_id, stable_url.clone(), Some("not-an-endpoint-id")).await;

    let urls = get_api_urls(&db, &test_config(peer_id, stable_url), true).await;

    assert!(!urls.contains_key(&peer_id));
}

#[test]
fn legacy_guardian_metadata_ignores_next_endpoint_and_keeps_stable_url() {
    #[derive(Deserialize)]
    struct LegacyGuardianMetadata {
        api_urls: Vec<SafeUrl>,
        pkarr_id_z32: String,
        timestamp_secs: u64,
    }

    let stable_url = SafeUrl::parse(&format!("iroh://{STABLE_ENDPOINT_ID}")).expect("valid URL");
    let metadata = GuardianMetadata::new(vec![stable_url.clone()], "pkarr-id".to_owned(), 1)
        .with_iroh_next_endpoint(NEXT_ENDPOINT_ID.to_owned());

    let legacy: LegacyGuardianMetadata =
        serde_json::from_slice(&serde_json::to_vec(&metadata).expect("serializes"))
            .expect("legacy clients ignore the new optional field");

    assert_eq!(legacy.api_urls, vec![stable_url]);
    assert_eq!(legacy.pkarr_id_z32, "pkarr-id");
    assert_eq!(legacy.timestamp_secs, 1);
}

#[test]
fn current_guardian_metadata_accepts_legacy_payload_without_next_endpoint() {
    let stable_url = SafeUrl::parse(&format!("iroh://{STABLE_ENDPOINT_ID}")).expect("valid URL");
    let legacy_payload = serde_json::json!({
        "api_urls": [stable_url],
        "pkarr_id_z32": "pkarr-id",
        "timestamp_secs": 1,
    });

    let metadata: GuardianMetadata =
        serde_json::from_value(legacy_payload).expect("legacy metadata remains valid");

    assert_eq!(metadata.iroh_next_endpoint, None);
}
