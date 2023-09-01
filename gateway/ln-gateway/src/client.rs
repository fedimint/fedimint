use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::PlainRootSecretStrategy;
use fedimint_client::ClientBuilder;
use fedimint_core::api::{DynGlobalApi, GlobalFederationApi, InviteCode, WsFederationApi};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::DatabaseTransaction;
use futures::StreamExt;
use lightning::routing::gossip::RoutingFees;

use crate::db::{FederationConfig, FederationIdKey, FederationIdKeyPrefix};
use crate::lnrpc_client::ILnRpcClient;
use crate::ng::GatewayClientGen;
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
        lnrpc: Arc<dyn ILnRpcClient>,
        old_client: Option<fedimint_client::Client>,
    ) -> Result<fedimint_client::Client> {
        let federation_id = config.config.global.federation_id;

        let mut registry = self.registry.clone();
        registry.attach(GatewayClientGen {
            lnrpc,
            node_pub_key,
            fees: config.fees,
            timelock_delta: config.timelock_delta,
            mint_channel_id: config.mint_channel_id,
        });

        let mut client_builder = ClientBuilder::default();
        client_builder.with_module_inits(registry);
        client_builder.with_primary_module(self.primary_module);
        client_builder.with_config(config.config);
        if let Some(old_client) = old_client {
            client_builder.with_old_client_database(old_client);
        } else {
            let db_path = self.work_dir.join(format!("{federation_id}.db"));
            let db = fedimint_rocksdb::RocksDb::open(db_path).map_err(|e| {
                GatewayError::DatabaseError(anyhow::anyhow!("Error opening rocksdb: {e:?}"))
            })?;
            client_builder.with_database(db);
        }

        client_builder
            // TODO: make this configurable?
            .build::<PlainRootSecretStrategy>()
            .await
            .map_err(GatewayError::ClientStateMachineError)
    }

    pub async fn create_config(
        &self,
        connect: InviteCode,
        mint_channel_id: u64,
        fees: RoutingFees,
    ) -> Result<FederationConfig> {
        let api: DynGlobalApi = WsFederationApi::from_invite_code(&[connect.clone()]).into();
        let client_config = api.download_client_config(&connect).await?;
        Ok(FederationConfig {
            mint_channel_id,
            timelock_delta: 10,
            fees,
            config: client_config,
        })
    }

    pub async fn save_config(
        &self,
        config: FederationConfig,
        mut dbtx: DatabaseTransaction<'_>,
    ) -> Result<()> {
        let id = config.config.global.federation_id;
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
