use std::fmt::Debug;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_client::module::gen::{ClientModuleGenRegistry, ClientModuleGenRegistryExt};
use fedimint_core::api::{
    DynFederationApi, GlobalFederationApi, WsClientConnectInfo, WsFederationApi,
};
use fedimint_core::config::{load_from_file, FederationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::dyn_newtype_define;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use mint_client::{module_decode_stubs, Client, GatewayClientConfig};
use secp256k1::{KeyPair, PublicKey};
use tracing::{debug, warn};
use url::Url;

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
        module_gens: ClientModuleGenRegistry,
    ) -> Result<GatewayClientConfig>;

    /// Save and persist the configuration of the gateway federation client
    fn save_config(&self, config: GatewayClientConfig) -> Result<()>;

    /// Load all gateway client configs from the work directory
    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>>;
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
        let federation_id = config.client_config.federation_id.clone();

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
        module_gens: ClientModuleGenRegistry,
    ) -> Result<GatewayClientConfig> {
        let api: DynFederationApi = WsFederationApi::from_urls(&connect).into();

        let client_config = api
            .download_client_config(&connect.id, module_gens.to_common())
            .await
            .expect("Failed to get client config");

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
        })
    }

    fn save_config(&self, config: GatewayClientConfig) -> Result<()> {
        let id = config.client_config.federation_id.to_string();
        let path: PathBuf = self.work_dir.join(format!("{id}.json"));

        if Path::new(&path).is_file() {
            if config
                == load_from_file::<GatewayClientConfig>(&path)
                    .expect("Could not load existing gateway client config")
            {
                debug!("Existing gateway client config has not changed");
                return Ok(());
            }

            panic!("Attempted to overwrite existing gateway client config")
            // TODO: Issue 1057: Safe persistence and migration of gateway
            // federation config
        }

        debug!("Saving gateway cfg in {}", path.display());
        let file = File::create(path).expect("Could not create gateway cfg file");
        serde_json::to_writer_pretty(file, &config).expect("Could not write gateway cfg");

        Ok(())
    }

    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>> {
        Ok(std::fs::read_dir(&self.work_dir)
            .map_err(|e| GatewayError::Other(anyhow::Error::new(e)))?
            .filter_map(|file_res| {
                let file = file_res.ok()?;
                if !file.file_type().ok()?.is_file() {
                    return None;
                }

                if file
                    .path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
                {
                    Some(file)
                } else {
                    None
                }
            })
            .filter_map(|file| {
                // FIXME: handle parsing errors
                debug!("Trying to load config file {:?}", file.path());
                load_from_file(&file.path())
                    .map_err(|e| warn!("Could not parse config: {}", e))
                    .ok()
            })
            .collect())
    }
}
