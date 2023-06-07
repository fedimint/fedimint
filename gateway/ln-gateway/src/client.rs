use std::fmt::Debug;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client_legacy::{module_decode_stubs, Client, GatewayClientConfig};
use fedimint_core::api::{DynGlobalApi, GlobalFederationApi, WsClientConnectInfo, WsFederationApi};
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::dyn_newtype_define;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use futures::StreamExt;
use lightning::routing::gossip::RoutingFees;
use secp256k1::{KeyPair, PublicKey};
use url::Url;

use crate::db::{FederationConfig, FederationIdKey, FederationIdKeyPrefix};
use crate::{GatewayError, Result};

pub trait IDbFactory: Debug {
    fn create_database(
        &self,
        federation_id: FederationId,
        path: PathBuf,
        decoders: ModuleDecoderRegistry,
    ) -> Result<Database>;
}

dyn_newtype_define!(
    /// Arc reference to a database factory
    #[derive(Clone)]
    pub DynDbFactory(Arc<IDbFactory>)
);

/// A factory that creates in-memory databases
#[derive(Default, Debug, Clone)]
pub struct MemDbFactory;

impl IDbFactory for MemDbFactory {
    fn create_database(
        &self,
        _federation_id: FederationId,
        _path: PathBuf,
        decoders: ModuleDecoderRegistry,
    ) -> Result<Database> {
        Ok(Database::new(MemDatabase::new(), decoders))
    }
}

/// A factory that creates RocksDb database instances
#[derive(Default, Debug, Clone)]
pub struct RocksDbFactory;

impl IDbFactory for RocksDbFactory {
    fn create_database(
        &self,
        federation_id: FederationId,
        path: PathBuf,
        decoders: ModuleDecoderRegistry,
    ) -> Result<Database> {
        let db_path = path.join(format!("{federation_id}.db"));
        let db = fedimint_rocksdb::RocksDb::open(db_path).expect("Error opening new rocks DB");
        Ok(Database::new(db, decoders))
    }
}

/// Trait for gateway federation client builders
#[async_trait]
pub trait IGatewayClientBuilder: Debug {
    /// Build a new gateway federation client
    async fn build(
        &self,
        config: GatewayClientConfig,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
    ) -> Result<Client<GatewayClientConfig>>;

    /// Create a new gateway federation client config from connect info
    async fn create_config(
        &self,
        connect: WsClientConnectInfo,
        mint_channel_id: u64,
        node_pubkey: PublicKey,
        fees: RoutingFees,
    ) -> Result<GatewayClientConfig>;

    /// Save and persist the configuration of the gateway federation client
    async fn save_config(
        &self,
        config: GatewayClientConfig,
        connection_string: String,
        dbtx: DatabaseTransaction<'_>,
    ) -> Result<()>;

    /// Load all gateway client configs from the work directory
    async fn load_configs(
        &self,
        dbtx: DatabaseTransaction<'_>,
        node_pub_key: PublicKey,
    ) -> Result<Vec<GatewayClientConfig>>;
}

dyn_newtype_define! {
    /// dyn newtype for a Gateway federation client builder
    #[derive(Clone)]
    pub DynGatewayClientBuilder(Arc<IGatewayClientBuilder>)
}

#[derive(Debug, Clone)]
pub struct StandardGatewayClientBuilder {
    work_dir: PathBuf,
    db_factory: DynDbFactory,
    gateway_api: Url,
}

impl StandardGatewayClientBuilder {
    pub fn new(work_dir: PathBuf, db_factory: DynDbFactory, gateway_api: Url) -> Self {
        Self {
            work_dir,
            db_factory,
            gateway_api,
        }
    }
}

#[async_trait]
impl IGatewayClientBuilder for StandardGatewayClientBuilder {
    async fn build(
        &self,
        config: GatewayClientConfig,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
    ) -> Result<Client<GatewayClientConfig>> {
        let federation_id = config.client_config.federation_id;

        let db = self.db_factory.create_database(
            federation_id,
            self.work_dir.clone(),
            module_decode_stubs(),
        )?;
        let ctx = secp256k1::Secp256k1::new();

        Ok(Client::new(config, decoders, module_gens, db, ctx).await)
    }

    async fn create_config(
        &self,
        connect: WsClientConnectInfo,
        mint_channel_id: u64,
        node_pubkey: PublicKey,
        fees: RoutingFees,
    ) -> Result<GatewayClientConfig> {
        let api: DynGlobalApi = WsFederationApi::from_connect_info(&[connect.clone()]).into();

        let client_config = api.download_client_config(&connect).await?;

        let mut rng = rand::rngs::OsRng;
        let ctx = secp256k1::Secp256k1::new();
        let kp_fed = KeyPair::new(&ctx, &mut rng);

        Ok(GatewayClientConfig {
            mint_channel_id,
            client_config,
            redeem_key: kp_fed,
            timelock_delta: 10,
            node_pub_key: node_pubkey,
            api: self.gateway_api.clone(),
            fees,
        })
    }

    async fn save_config(
        &self,
        config: GatewayClientConfig,
        connection_string: String,
        mut dbtx: DatabaseTransaction<'_>,
    ) -> Result<()> {
        let id = config.client_config.federation_id;
        let federation_config = FederationConfig {
            mint_channel_id: config.mint_channel_id,
            redeem_key: config.redeem_key,
            timelock_delta: config.timelock_delta,
            connection_string,
            fees: config.fees,
        };
        dbtx.insert_new_entry(&FederationIdKey { id }, &federation_config)
            .await;
        dbtx.commit_tx_result()
            .await
            .map_err(|_| GatewayError::DatabaseError)
    }

    async fn load_configs(
        &self,
        mut dbtx: DatabaseTransaction<'_>,
        node_pub_key: PublicKey,
    ) -> Result<Vec<GatewayClientConfig>> {
        let federations = dbtx
            .find_by_prefix(&FederationIdKeyPrefix)
            .await
            .collect::<Vec<(FederationIdKey, FederationConfig)>>()
            .await;
        let mut configs = Vec::new();
        for (_id, config) in federations {
            let connect =
                WsClientConnectInfo::from_str(&config.connection_string).map_err(|e| {
                    GatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
                })?;

            let gateway_config = self
                .create_config(connect, config.mint_channel_id, node_pub_key, config.fees)
                .await?;
            configs.push(gateway_config);
        }

        Ok(configs)
    }
}
