use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{IDatabaseTransactionOpsCoreTyped as _, IRawDatabaseExt as _};
use fedimint_core::net::guardian_metadata::GuardianMetadata;
use fedimint_core::util::SafeUrl;
use fedimint_core::{PeerId, secp256k1};

use super::{
    GuardianMetadataKey, ensure_iroh_next_remains_available, next_metadata_timestamp,
    reconcile_api_urls, reconcile_guardian_metadata_record, reconcile_iroh_next_endpoint,
};

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

#[test]
fn reconciliation_applies_only_authoritative_api_url_override() {
    let mut metadata = GuardianMetadata::new(
        vec!["wss://old.example".parse().expect("valid URL")],
        "administrator-pkarr-id".to_owned(),
        42,
    );
    metadata.iroh_next_endpoint = Some("server-owned-iroh-id".to_owned());
    let override_urls = vec![
        "ws://guardian.example".parse().expect("valid URL"),
        "ws://guardian.onion".parse().expect("valid URL"),
    ];

    assert!(reconcile_api_urls(&mut metadata, &override_urls));
    assert_eq!(metadata.api_urls, override_urls);
    assert_eq!(metadata.pkarr_id_z32, "administrator-pkarr-id");
    assert_eq!(
        metadata.iroh_next_endpoint.as_deref(),
        Some("server-owned-iroh-id")
    );
    assert_eq!(metadata.timestamp_secs, 42);
    assert!(!reconcile_api_urls(&mut metadata, &override_urls));
}

#[test]
fn reconciliation_advances_timestamp_strictly() {
    assert_eq!(next_metadata_timestamp(100, None).expect("valid"), 100);
    assert_eq!(next_metadata_timestamp(100, Some(99)).expect("valid"), 100);
    assert_eq!(next_metadata_timestamp(100, Some(100)).expect("valid"), 101);
    assert_eq!(next_metadata_timestamp(100, Some(200)).expect("valid"), 201);
    assert!(next_metadata_timestamp(100, Some(u64::MAX)).is_err());
}

#[tokio::test]
async fn durable_reconciliation_preserves_and_overrides_owned_fields() {
    let db = MemDatabase::new().into_database();
    let key = GuardianMetadataKey(PeerId::from(0));
    let secret_key = secp256k1::SecretKey::from_slice(&[42; 32]).expect("valid secret key");
    let consensus_url: SafeUrl = "wss://consensus.example".parse().expect("valid URL");
    let initial = GuardianMetadata::new(vec![consensus_url.clone()], "initial-pkarr".to_owned(), 0);

    assert!(
        reconcile_guardian_metadata_record(
            &db,
            key.clone(),
            initial.clone(),
            &secret_key,
            None,
            &[],
        )
        .await
        .expect("missing metadata should be initialized")
    );
    let stored = db
        .begin_transaction_nc()
        .await
        .get_value(&key)
        .await
        .expect("metadata was stored");
    assert_eq!(stored.guardian_metadata().api_urls, [consensus_url]);
    assert!(
        !reconcile_guardian_metadata_record(
            &db,
            key.clone(),
            initial.clone(),
            &secret_key,
            None,
            &[],
        )
        .await
        .expect("unchanged metadata should reconcile")
    );

    let ctx = secp256k1::Secp256k1::new();
    let administrator_timestamp = stored.guardian_metadata().timestamp_secs;
    let administrator_metadata = GuardianMetadata::new(
        vec!["wss://administrator.example".parse().expect("valid URL")],
        "administrator-pkarr".to_owned(),
        administrator_timestamp,
    )
    .with_iroh_next_endpoint("persisted-iroh-id".to_owned())
    .sign(&ctx, &secret_key.keypair(&ctx));
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&key, &administrator_metadata).await;
    dbtx.commit_tx().await;

    assert!(
        !reconcile_guardian_metadata_record(
            &db,
            key.clone(),
            initial.clone(),
            &secret_key,
            Some("persisted-iroh-id".to_owned()),
            &[],
        )
        .await
        .expect("omitting override should preserve administrator metadata")
    );

    let override_urls = vec![
        "ws://guardian.example".parse().expect("valid URL"),
        "ws://guardian.onion".parse().expect("valid URL"),
    ];
    assert!(
        reconcile_guardian_metadata_record(
            &db,
            key.clone(),
            initial,
            &secret_key,
            Some("persisted-iroh-id".to_owned()),
            &override_urls,
        )
        .await
        .expect("override should reconcile")
    );
    let overridden = db
        .begin_transaction_nc()
        .await
        .get_value(&key)
        .await
        .expect("overridden metadata was stored");
    assert_eq!(overridden.guardian_metadata().api_urls, override_urls);
    assert_eq!(
        overridden.guardian_metadata().pkarr_id_z32,
        "administrator-pkarr"
    );
    assert_eq!(
        overridden.guardian_metadata().iroh_next_endpoint.as_deref(),
        Some("persisted-iroh-id")
    );
    assert!(
        overridden.guardian_metadata().timestamp_secs > administrator_timestamp,
        "re-signed metadata must be strictly newer"
    );
    assert!(
        !reconcile_guardian_metadata_record(
            &db,
            key.clone(),
            overridden.guardian_metadata().clone(),
            &secret_key,
            Some("persisted-iroh-id".to_owned()),
            &override_urls,
        )
        .await
        .expect("repeated override should be idempotent")
    );

    let exhausted = GuardianMetadata {
        timestamp_secs: u64::MAX,
        ..overridden.guardian_metadata().clone()
    }
    .sign(&ctx, &secret_key.keypair(&ctx));
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&key, &exhausted).await;
    dbtx.commit_tx().await;
    let replacement = vec!["ws://replacement.onion".parse().expect("valid URL")];
    assert!(
        reconcile_guardian_metadata_record(
            &db,
            key,
            overridden.guardian_metadata().clone(),
            &secret_key,
            Some("persisted-iroh-id".to_owned()),
            &replacement,
        )
        .await
        .expect_err("timestamp exhaustion must stop reconciliation")
        .to_string()
        .contains("timestamp is exhausted")
    );
}

#[tokio::test]
async fn missing_record_prefers_override_to_consensus_bootstrap() {
    let db = MemDatabase::new().into_database();
    let key = GuardianMetadataKey(PeerId::from(0));
    let secret_key = secp256k1::SecretKey::from_slice(&[43; 32]).expect("valid secret key");
    let initial = GuardianMetadata::new(
        vec!["wss://consensus.example".parse().expect("valid URL")],
        "initial-pkarr".to_owned(),
        0,
    );
    let override_urls = vec!["ws://guardian.onion".parse().expect("valid URL")];

    reconcile_guardian_metadata_record(
        &db,
        key.clone(),
        initial,
        &secret_key,
        None,
        &override_urls,
    )
    .await
    .expect("missing metadata should initialize from override");

    let stored = db
        .begin_transaction_nc()
        .await
        .get_value(&key)
        .await
        .expect("metadata was stored");
    assert_eq!(stored.guardian_metadata().api_urls, override_urls);
}
