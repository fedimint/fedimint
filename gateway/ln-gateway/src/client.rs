use std::{
    fmt::Debug,
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

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

/// Trait for gateway federation client builders
#[async_trait]
pub trait IGatewayClientBuilder: Debug {
    /// Build a new gateway federation client
    fn build(&self, config: GatewayClientConfig) -> Result<Client<GatewayClientConfig>>;

    /// Create a new gateway federation client config from connect info
    async fn create_config(
        &self,
        connect: WsFederationConnect,
        node_pubkey: PublicKey,
        announce_address: Url,
    ) -> Result<GatewayClientConfig>;

    /// Create a new database for the gateway federation client
    fn create_database(&self, federation_id: FederationId) -> Result<Database>;

    /// Save and persist the configuration of the gateway federation client
    fn save_config(&self, config: GatewayClientConfig) -> Result<()>;

    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>>;
}

dyn_newtype_define! {
  /// Arc reference to a Gateway federation client builder
  #[derive(Clone)]
  pub GatewayClientBuilder(Arc<IGatewayClientBuilder>)
}

#[derive(Debug, Clone)]
pub struct RocksDbGatewayClientBuilder {
    pub work_dir: PathBuf,
}

/// Default gateway clinet builder which constructs clients with RocksDb
/// and saves the config at the given work directory
impl RocksDbGatewayClientBuilder {
    pub fn new(work_dir: PathBuf) -> Self {
        Self { work_dir }
    }
}

/// Builds a new federation client with RocksDb
/// On successful build, the configuration is saved to a file at the builder work directory
#[async_trait]
impl IGatewayClientBuilder for RocksDbGatewayClientBuilder {
    fn build(&self, config: GatewayClientConfig) -> Result<Client<GatewayClientConfig>> {
        let federation_id = FederationId(config.client_config.federation_name.clone());

        let db = self.create_database(federation_id)?;
        let ctx = secp256k1::Secp256k1::new();

        Ok(Client::new(config, db, ctx))
    }

    /// Create a client database
    fn create_database(&self, federation_id: FederationId) -> Result<Database> {
        let db_path = self.work_dir.join(format!("{}.db", federation_id.hash()));
        let db = fedimint_rocksdb::RocksDb::open(db_path)
            .expect("Error opening DB")
            .into();
        Ok(db)
    }

    async fn create_config(
        &self,
        connect: WsFederationConnect,
        node_pubkey: PublicKey,
        announce_address: Url,
    ) -> Result<GatewayClientConfig> {
        create_gateway_client_cfg(connect, node_pubkey, announce_address).await
    }

    /// Persist federation client cfg to [`<federation_id>.json`] file
    fn save_config(&self, config: GatewayClientConfig) -> Result<()> {
        let federation_id = FederationId(config.client_config.federation_name.clone());

        let path: PathBuf = self.work_dir.join(format!("{}.json", federation_id.hash()));

        if !Path::new(&path).is_file() {
            debug!("Creating new gateway cfg file at {}", path.display());
            let file = File::create(path).expect("Could not create gateway cfg file");
            serde_json::to_writer_pretty(file, &config).expect("Could not write gateway cfg");
        } else {
            debug!("Gateway cfg file already exists at {}", path.display());
            let file = File::open(path).expect("Could not load gateway cfg file");
            serde_json::to_writer_pretty(file, &config).expect("Could not write gateway cfg");
        }

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

// Builds a new federation client with MemoryDb
#[derive(Default, Debug, Clone)]
pub struct MemoryDbGatewayClientBuilder {}

#[async_trait]
impl IGatewayClientBuilder for MemoryDbGatewayClientBuilder {
    fn build(&self, config: GatewayClientConfig) -> Result<Client<GatewayClientConfig>> {
        let federation_id = FederationId(config.client_config.federation_name.clone());

        let db = self.create_database(federation_id)?;
        let ctx = secp256k1::Secp256k1::new();

        Ok(Client::new(config, db, ctx))
    }

    /// Create a client database
    fn create_database(&self, _federation_id: FederationId) -> Result<Database> {
        Ok(MemDatabase::new().into())
    }

    async fn create_config(
        &self,
        connect: WsFederationConnect,
        node_pubkey: PublicKey,
        announce_address: Url,
    ) -> Result<GatewayClientConfig> {
        create_gateway_client_cfg(connect, node_pubkey, announce_address).await
    }

    /// Persist gateway federation client cfg
    fn save_config(&self, _config: GatewayClientConfig) -> Result<()> {
        unimplemented!()
    }

    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>> {
        Ok(vec![])
    }
}

async fn create_gateway_client_cfg(
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
