use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use fedimint_api::{
    db::{mem_impl::MemDatabase, Database},
    dyn_newtype_define,
};
use mint_client::{Client, FederationId, GatewayClientConfig};
use tracing::debug;

use crate::Result;

/// Trait for gateway federation client builders
pub trait IGatewayClientBuilder {
    /// Build a new gateway federation client
    fn build(&self, config: GatewayClientConfig) -> Result<Client<GatewayClientConfig>>;

    /// Create a new database for the gateway federation client
    fn create_database(&self, federation_id: FederationId) -> Result<Database>;

    /// Save and persist the configuration of the gateway federation client
    fn save_config(&self, config: GatewayClientConfig) -> Result<()>;
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
impl IGatewayClientBuilder for RocksDbGatewayClientBuilder {
    fn build(&self, config: GatewayClientConfig) -> Result<Client<GatewayClientConfig>> {
        let federation_id = FederationId(config.client_config.federation_name.clone());

        let db = self.create_database(federation_id)?;
        let ctx = secp256k1::Secp256k1::new();

        Ok(Client::new(config, db, ctx))
    }

    /// Create a client database
    fn create_database(&self, federation_id: FederationId) -> Result<Database> {
        let db_path = self.work_dir.join(format!("{}.db", federation_id.0));
        let db = fedimint_rocksdb::RocksDb::open(db_path)
            .expect("Error opening DB")
            .into();
        Ok(db)
    }

    /// Persist federation client cfg to [`<federation_id>.json`] file
    fn save_config(&self, config: GatewayClientConfig) -> Result<()> {
        let federation_id = FederationId(config.client_config.federation_name.clone());
        let path: PathBuf = self.work_dir.join(format!("{}.json", federation_id.0));

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
}

// Builds a new federation client with MemoryDb
#[derive(Default, Debug, Clone)]
pub struct MemoryDbGatewayClientBuilder {}

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

    /// Persist gateway federation client cfg
    fn save_config(&self, _config: GatewayClientConfig) -> Result<()> {
        unimplemented!()
    }
}
