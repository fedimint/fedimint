use anyhow::ensure;
use fedimint_client::db::{ClientConfigKey, ClientConfigKeyV0};
use fedimint_core::config::{ClientConfigV0, FederationId, GlobalClientConfigV0};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::CoreConsensusVersion;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_logging::TracingSetup;

use crate::db::{snapshot_db_migrations_with_decoders, validate_migrations_core_client};
/// Create a client database with version 0 data. The database produced is
/// not intended to be real data or semantically correct. It is only
/// intended to provide coverage when reading the database
/// in future code versions. This function should not be updated when
/// database keys/values change - instead a new function should be added
/// that creates a new database backup that can be tested.
async fn create_client_db_with_v0_data(db: Database) {
    let mut dbtx = db.begin_transaction().await;

    let federation_id = FederationId::dummy();

    let client_config_v0 = ClientConfigV0 {
        global: GlobalClientConfigV0 {
            api_endpoints: Default::default(),
            consensus_version: CoreConsensusVersion::new(0, 0),
            meta: Default::default(),
        },
        modules: Default::default(),
    };

    let client_config_key_v0 = ClientConfigKeyV0 { id: federation_id };

    dbtx.insert_new_entry(&client_config_key_v0, &client_config_v0)
        .await;

    dbtx.commit_tx().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
    snapshot_db_migrations_with_decoders(
        "fedimint-client",
        |db| {
            Box::pin(async {
                create_client_db_with_v0_data(db).await;
            })
        },
        ModuleDecoderRegistry::default(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_client_db_migrations() -> anyhow::Result<()> {
    let _ = TracingSetup::default().init();

    validate_migrations_core_client("fedimint-client", |db| async move {
        let mut dbtx = db.begin_transaction_nc().await;
        // Checks that client config migrated to ClientConfig with broadcast_public_keys
        ensure!(
            dbtx.get_value(&ClientConfigKey).await.is_some(),
            "Client config migration to v0 failed"
        );

        Ok(())
    })
    .await?;

    Ok(())
}
