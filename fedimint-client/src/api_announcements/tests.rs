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

use super::get_api_urls;
use crate::guardian_metadata::GuardianMetadataKey;

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
    let stable_url = SafeUrl::parse("iroh://stable-endpoint").expect("valid URL");
    let next_endpoint = "next-endpoint";
    insert_guardian_metadata(&db, peer_id, stable_url.clone(), Some(next_endpoint)).await;

    let urls = get_api_urls(&db, &test_config(peer_id, stable_url), true).await;

    assert_eq!(
        urls.get(&peer_id),
        Some(&SafeUrl::parse(&format!("iroh://{next_endpoint}")).expect("valid URL"))
    );
}

#[tokio::test]
async fn missing_endpoint_or_disabled_iroh_next_does_not_rewrite_iroh_url() {
    let stable_url = SafeUrl::parse("iroh://stable-endpoint").expect("valid URL");
    let peer_id = PeerId::from(0);

    for (advertised_endpoint, client_iroh_next_enabled) in
        [(None, true), (Some("next-endpoint"), false)]
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
    insert_guardian_metadata(&db, peer_id, stable_url.clone(), Some("next-endpoint")).await;

    let urls = get_api_urls(&db, &test_config(peer_id, stable_url.clone()), true).await;

    assert_eq!(urls.get(&peer_id), Some(&stable_url));
}
