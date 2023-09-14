use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::PlainRootSecretStrategy;
use fedimint_client::{get_config_from_db, ClientBuilder};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use futures::StreamExt;

use crate::db::{FederationConfig, FederationIdKey, FederationIdKeyPrefix};
use crate::lnrpc_client::ILnRpcClient;
use crate::state_machine::GatewayClientGen;
use crate::{GatewayError, Result};

#[derive(Debug, Clone)]
pub struct StandardGatewayClientBuilder {
    work_dir: PathBuf,
    registry: ClientModuleInitRegistry,
    primary_module: ModuleInstanceId,
}

impl StandardGatewayClientBuilder {
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

impl StandardGatewayClientBuilder {
    pub async fn build(
        &self,
        config: FederationConfig,
        node_pub_key: secp256k1::PublicKey,
        lightning_alias: String,
        lnrpc: Arc<dyn ILnRpcClient>,
        old_client: Option<fedimint_client::Client>,
    ) -> Result<fedimint_client::Client> {
        let FederationConfig {
            invite_code,
            mint_channel_id,
            timelock_delta,
            fees,
        } = config;
        let federation_id = invite_code.id;

        let mut registry = self.registry.clone();
        registry.attach(GatewayClientGen {
            lnrpc,
            node_pub_key,
            lightning_alias,
            fees,
            timelock_delta,
            mint_channel_id,
        });

        let mut client_builder = ClientBuilder::default();
        client_builder.with_module_inits(registry);
        client_builder.with_primary_module(self.primary_module);
        if let Some(old_client) = old_client {
            client_builder.with_old_client_database(old_client);
        } else {
            let db_path = self.work_dir.join(format!("{federation_id}.db"));
            {
                let rocksdb = fedimint_rocksdb::RocksDb::open(db_path.clone()).map_err(|e| {
                    GatewayError::DatabaseError(anyhow::anyhow!("Error opening rocksdb: {e:?}"))
                })?;

                // Initialize a client database to check if a config was previously saved in it
                let db = Database::new(rocksdb, ModuleDecoderRegistry::default());
                if (get_config_from_db(&db).await).is_none() {
                    client_builder.with_invite_code(invite_code);
                }
            }

            let rocksdb = fedimint_rocksdb::RocksDb::open(db_path.clone()).map_err(|e| {
                GatewayError::DatabaseError(anyhow::anyhow!("Error opening rocksdb: {e:?}"))
            })?;
            client_builder.with_database(rocksdb);
        }

        client_builder
            // TODO: make this configurable?
            .build::<PlainRootSecretStrategy>()
            .await
            .map_err(GatewayError::ClientStateMachineError)
    }

    pub async fn save_config(
        &self,
        config: FederationConfig,
        mut dbtx: DatabaseTransaction<'_>,
    ) -> Result<()> {
        let id = config.invite_code.id;
        dbtx.insert_entry(&FederationIdKey { id }, &config).await;
        dbtx.commit_tx_result()
            .await
            .map_err(GatewayError::DatabaseError)
    }

    pub async fn load_configs(
        &self,
        mut dbtx: DatabaseTransaction<'_>,
    ) -> Result<Vec<FederationConfig>> {
        Ok(dbtx
            .find_by_prefix(&FederationIdKeyPrefix)
            .await
            .collect::<BTreeMap<FederationIdKey, FederationConfig>>()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>())
    }
}
