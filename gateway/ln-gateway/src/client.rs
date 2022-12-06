use std::{fmt::Debug, fs::File, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use fedimint_api::{
    config::ClientConfig,
    db::{mem_impl::MemDatabase, Database},
    dyn_newtype_define, NumPeers,
};
use fedimint_server::config::load_from_file;
use mint_client::{
    api::{WsFederationApi, WsFederationConnect},
    query::CurrentConsensus,
    Client, FederationId, GatewayClientConfig,
};
use secp256k1::{KeyPair, PublicKey};
use tracing::{debug, warn};
use url::Url;

use crate::{LnGatewayError, Result};

pub trait IDbFactory: Debug {
    fn create_database(&self, federation_id: FederationId, path: PathBuf) -> Result<Database>;
}

dyn_newtype_define!(
    /// Arc reference to a database factory
    #[derive(Clone)]
    pub DbFactory(Arc<IDbFactory>)
);

/// A factory that creates in-memory databases
#[derive(Default, Debug, Clone)]
pub struct MemDbFactory;

impl IDbFactory for MemDbFactory {
    fn create_database(&self, _federation_id: FederationId, _path: PathBuf) -> Result<Database> {
        Ok(MemDatabase::new().into())
    }
}

/// A factory that creates RocksDb database instances
#[derive(Default, Debug, Clone)]
pub struct RocksDbFactory;

impl IDbFactory for RocksDbFactory {
    fn create_database(&self, federation_id: FederationId, path: PathBuf) -> Result<Database> {
        let db_path = path.join(format!("{}.db", federation_id.hash()));
        let db = fedimint_rocksdb::RocksDb::open(db_path)
            .expect("Error opening new rocks DB")
            .into();
        Ok(db)
    }
}

/// Trait for gateway federation client builders
#[async_trait]
pub trait IGatewayClientBuilder: Debug {
    /// Build a new gateway federation client
    async fn build(&self, config: GatewayClientConfig) -> Result<Client<GatewayClientConfig>>;

    /// Create a new gateway federation client config from connect info
    async fn create_config(
        &self,
        connect: WsFederationConnect,
        node_pubkey: PublicKey,
        announce_address: Url,
    ) -> Result<GatewayClientConfig>;

    /// Save and persist the configuration of the gateway federation client
    fn save_config(&self, config: GatewayClientConfig) -> Result<()>;

    /// Load all gateway client configs from the work directory
    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>>;
}

dyn_newtype_define! {
    /// dyn newtype for a Gateway federation client builder
    #[derive(Clone)]
    pub GatewayClientBuilder(Arc<IGatewayClientBuilder>)
}

#[derive(Debug, Clone)]
pub struct StandardGatewayClientBuilder {
    work_dir: PathBuf,
    db_factory: DbFactory,
}

impl StandardGatewayClientBuilder {
    pub fn new(work_dir: PathBuf, db_factory: DbFactory) -> Self {
        Self {
            work_dir,
            db_factory,
        }
    }
}

#[async_trait]
impl IGatewayClientBuilder for StandardGatewayClientBuilder {
    async fn build(&self, config: GatewayClientConfig) -> Result<Client<GatewayClientConfig>> {
        let federation_id = FederationId(config.client_config.federation_name.clone());

        let db = self
            .db_factory
            .create_database(federation_id, self.work_dir.clone())?;
        let ctx = secp256k1::Secp256k1::new();

        Ok(Client::new(config, db, ctx).await)
    }

    async fn create_config(
        &self,
        connect: WsFederationConnect,
        node_pubkey: PublicKey,
        announce_address: Url,
    ) -> Result<GatewayClientConfig> {
        let api = WsFederationApi::new(connect.members);

        let client_cfg: ClientConfig = api
            .request(
                "/config",
                (),
                CurrentConsensus::new(api.peers().one_honest()),
            )
            .await
            .expect("Failed to get client config");

        let mut rng = rand::rngs::OsRng;
        let ctx = secp256k1::Secp256k1::new();
        let kp_fed = KeyPair::new(&ctx, &mut rng);

        Ok(GatewayClientConfig {
            client_config: client_cfg,
            redeem_key: kp_fed,
            timelock_delta: 10,
            node_pub_key: node_pubkey,
            api: announce_address,
        })
    }

    fn save_config(&self, config: GatewayClientConfig) -> Result<()> {
        let federation_id = FederationId(config.client_config.federation_name.clone());

        let path: PathBuf = self.work_dir.join(format!("{}.json", federation_id.hash()));

        let file = File::create(path).expect("Could not create gateway cfg file");
        serde_json::to_writer_pretty(file, &config).expect("Could not write gateway cfg");

        // TODO: Safely save gateway configs without overwriting existing ones

        Ok(())
    }

    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>> {
        Ok(std::fs::read_dir(&self.work_dir)
            .map_err(|e| LnGatewayError::Other(anyhow::Error::new(e)))?
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
