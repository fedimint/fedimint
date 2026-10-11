use std::time::Duration;

use fedimint_client_module::meta::{LegacyMetaSource, MetaFieldKey, MetaFieldValue};
use fedimint_core::config::META_FEDERATION_NAME_KEY;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{IDatabaseTransactionOpsCoreTyped, IRawDatabaseExt};
use serde_json::json;

use super::MetaService;
use crate::db;

#[tokio::test]
async fn cached_field_does_not_wait_for_initial_fetch() {
    let service = MetaService::new(LegacyMetaSource::default());
    let db = MemDatabase::new().into_database();

    // No background task is started, so initialization can never complete.
    let value = tokio::time::timeout(
        Duration::from_secs(1),
        service.get_cached_field::<String>(&db, META_FEDERATION_NAME_KEY),
    )
    .await
    .expect("cache-only read must not wait for the metadata source");
    assert!(value.is_none());
}

#[tokio::test]
async fn cached_field_reads_names_and_tolerates_missing_or_invalid_names() {
    let service = MetaService::new(LegacyMetaSource::default());
    let database = MemDatabase::new().into_database();
    let mut dbtx = database.begin_transaction().await;
    dbtx.insert_entry(
        &db::MetaServiceInfoKey,
        &db::MetaServiceInfo {
            last_updated: fedimint_core::time::now(),
            revision: 0,
        },
    )
    .await;
    dbtx.commit_tx().await;

    for (value, expected) in [
        (None, None),
        (Some(json!("123")), Some("123")),
        (Some(json!(42)), None),
        (Some(json!(null)), None),
    ] {
        let mut dbtx = database.begin_transaction().await;
        let key = db::MetaFieldKey(MetaFieldKey(META_FEDERATION_NAME_KEY.to_owned()));
        if let Some(value) = value {
            dbtx.insert_entry(&key, &db::MetaFieldValue(MetaFieldValue(value)))
                .await;
        } else {
            dbtx.remove_entry(&key).await;
        }
        dbtx.commit_tx().await;
        assert_eq!(
            service
                .get_cached_field::<String>(&database, META_FEDERATION_NAME_KEY)
                .await
                .expect("metadata cache is initialized")
                .value
                .as_deref(),
            expected
        );
    }
}
