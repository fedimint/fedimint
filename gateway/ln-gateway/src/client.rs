use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{Client, FederationInfo};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Committable, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use futures::StreamExt;
use rand::thread_rng;
use tracing::info;

use crate::db::{FederationConfig, FederationIdKey, FederationIdKeyPrefix};
use crate::lnrpc_client::ILnRpcClient;
use crate::state_machine::GatewayClientInit;
use crate::{FederationToClientMap, GatewayError, Result, ScidToFederationMap};

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
    #[allow(clippy::too_many_arguments)]
    pub async fn build(
        &self,
        config: FederationConfig,
        node_pub_key: secp256k1::PublicKey,
        lightning_alias: String,
        lnrpc: Arc<dyn ILnRpcClient>,
        all_clients: FederationToClientMap,
        all_scids: ScidToFederationMap,
        old_client: Option<fedimint_client::ClientArc>,
        gateway_db: Database,
    ) -> Result<fedimint_client::ClientArc> {
        let FederationConfig {
            invite_code,
            mint_channel_id,
            timelock_delta,
            fees,
        } = config;
        let federation_id = invite_code.federation_id();

        let mut registry = self.registry.clone();
        registry.attach(GatewayClientInit {
            lnrpc,
            all_clients,
            all_scids,
            node_pub_key,
            lightning_alias,
            fees,
            timelock_delta,
            mint_channel_id,
            gateway_db,
        });

        let db_source = if let Some(old_client) = old_client {
            fedimint_client::DatabaseSource::Reuse(old_client)
        } else {
            let db_path = self.work_dir.join(format!("{federation_id}.db"));

            let rocksdb = fedimint_rocksdb::RocksDb::open(db_path.clone()).map_err(|e| {
                GatewayError::DatabaseError(anyhow::anyhow!("Error opening rocksdb: {e:?}"))
            })?;
            let db = Database::new(rocksdb, ModuleDecoderRegistry::default());

            fedimint_client::DatabaseSource::Fresh(db)
        };

        let mut client_builder = Client::builder(db_source);
        client_builder.with_module_inits(registry);
        client_builder.with_primary_module(self.primary_module);

        let client_secret =
            match Client::load_decodable_client_secret::<[u8; 64]>(client_builder.db()).await {
                Ok(secret) => secret,
                Err(_) => {
                    info!("Generating secret and writing to client storage");
                    let secret = PlainRootSecretStrategy::random(&mut thread_rng());
                    Client::store_encodable_client_secret(client_builder.db(), secret)
                        .await
                        .map_err(GatewayError::ClientStateMachineError)?;
                    secret
                }
            };

        let root_secret = PlainRootSecretStrategy::to_root_secret(&client_secret);
        if Client::is_initialized(client_builder.db()).await {
            client_builder
                // TODO: make this configurable?
                .open(root_secret)
                .await
        } else {
            let federation_info = FederationInfo::from_invite_code(invite_code.clone()).await?;
            client_builder
                // TODO: make this configurable?
                .join(
                    root_secret,
                    federation_info.config().to_owned(),
                    invite_code,
                )
                .await
        }
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
