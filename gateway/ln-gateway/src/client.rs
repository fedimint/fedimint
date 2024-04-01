use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::Client;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Committable, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use futures::StreamExt;
use rand::thread_rng;
use tracing::info;

use crate::db::{FederationConfig, FederationIdKey, FederationIdKeyPrefix};
use crate::state_machine::GatewayClientInit;
use crate::{Gateway, GatewayError, Result};

#[derive(Debug, Clone)]
pub struct GatewayClientBuilder {
    work_dir: PathBuf,
    registry: ClientModuleInitRegistry,
    primary_module: ModuleInstanceId,
}

impl GatewayClientBuilder {
    pub fn new(
        work_dir: PathBuf,
        registry: ClientModuleInitRegistry,
        primary_module: ModuleInstanceId,
    ) -> Self {
        Self {
            work_dir,
            registry,
            primary_module,
        }
    }
}

impl GatewayClientBuilder {
    pub async fn build(
        &self,
        config: FederationConfig,
        gateway: Gateway,
    ) -> Result<fedimint_client::ClientHandleArc> {
        let FederationConfig {
            invite_code,
            mint_channel_id,
            timelock_delta,
            ..
        } = config;
        let federation_id = invite_code.federation_id();

        let mut registry = self.registry.clone();
        registry.attach(GatewayClientInit {
            timelock_delta,
            mint_channel_id,
            gateway,
        });

        let db_path = self.work_dir.join(format!("{federation_id}.db"));

        let rocksdb = fedimint_rocksdb::RocksDb::open(db_path.clone()).map_err(|e| {
            GatewayError::DatabaseError(anyhow::anyhow!("Error opening rocksdb: {e:?}"))
        })?;
        let db = Database::new(rocksdb, ModuleDecoderRegistry::default());

        let mut client_builder = Client::builder(db);
        client_builder.with_module_inits(registry);
        client_builder.with_primary_module(self.primary_module);

        let client_secret =
            match Client::load_decodable_client_secret::<[u8; 64]>(client_builder.db_no_decoders())
                .await
            {
                Ok(secret) => secret,
                Err(_) => {
                    info!("Generating secret and writing to client storage");
                    let secret = PlainRootSecretStrategy::random(&mut thread_rng());
                    Client::store_encodable_client_secret(client_builder.db_no_decoders(), secret)
                        .await
                        .map_err(GatewayError::ClientStateMachineError)?;
                    secret
                }
            };

        let root_secret = PlainRootSecretStrategy::to_root_secret(&client_secret);
        if Client::is_initialized(client_builder.db_no_decoders()).await {
            client_builder
                // TODO: make this configurable?
                .open(root_secret)
                .await
        } else {
            let client_config = ClientConfig::download_from_invite_code(&invite_code).await?;
            client_builder
                // TODO: make this configurable?
                .join(root_secret, client_config.to_owned())
                .await
        }
        .map(Arc::new)
        .map_err(GatewayError::ClientStateMachineError)
    }

    pub async fn save_config(
        &self,
        config: FederationConfig,
        mut dbtx: DatabaseTransaction<'_, Committable>,
    ) -> Result<()> {
        let id = config.invite_code.federation_id();
        dbtx.insert_entry(&FederationIdKey { id }, &config).await;
        dbtx.commit_tx_result()
            .await
            .map_err(GatewayError::DatabaseError)
    }

    pub async fn load_configs(&self, mut dbtx: DatabaseTransaction<'_>) -> Vec<FederationConfig> {
        dbtx.find_by_prefix(&FederationIdKeyPrefix)
            .await
            .collect::<BTreeMap<FederationIdKey, FederationConfig>>()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>()
    }
}
