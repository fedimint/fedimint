use std::collections::BTreeSet;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::db::ClientConfigKey;
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::{Client, ClientBuilder, RootSecret};
use fedimint_client_module::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::FederationId;
use fedimint_core::db::{Database, IReadDatabaseTransactionOpsTyped};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_derive_secret::DerivableSecret;
use fedimint_gateway_common::FederationConfig;
use fedimint_gateway_server_db::GatewayDbExt as _;
use fedimint_gw_client::GatewayClientInit;
use fedimint_gwv2_client::GatewayClientInitV2;

use crate::config::DatabaseBackend;
use crate::error::AdminGatewayError;
use crate::{AdminResult, Gateway};

#[derive(Debug, Clone)]
pub struct GatewayClientBuilder {
    work_dir: PathBuf,
    registry: ClientModuleInitRegistry,
    db_backend: DatabaseBackend,
    connectors: ConnectorRegistry,
}

impl GatewayClientBuilder {
    pub async fn new(
        work_dir: PathBuf,
        registry: ClientModuleInitRegistry,
        db_backend: DatabaseBackend,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            connectors: ConnectorRegistry::build_from_client_env()?.bind().await?,
            work_dir,
            registry,
            db_backend,
        })
    }

    pub fn data_dir(&self) -> PathBuf {
        self.work_dir.clone()
    }

    /// Reads a plain root secret from a database to construct a database.
    /// Only used for "legacy" federations before v0.5.0
    async fn client_plainrootsecret(&self, db: &Database) -> AdminResult<DerivableSecret> {
        let client_secret = Client::load_decodable_client_secret::<[u8; 64]>(db)
            .await
            .map_err(AdminGatewayError::ClientCreationError)?;
        Ok(PlainRootSecretStrategy::to_root_secret(&client_secret))
    }

    /// Constructs the client builder with the modules, database, and connector
    /// used to create clients for connected federations.
    async fn create_client_builder(
        &self,
        federation_config: &FederationConfig,
        gateway: Arc<Gateway>,
    ) -> AdminResult<ClientBuilder> {
        let FederationConfig {
            federation_index, ..
        } = federation_config.to_owned();

        let mut registry = self.registry.clone();

        registry.attach(GatewayClientInit {
            federation_index,
            lightning_manager: gateway.clone(),
        });

        registry.attach(GatewayClientInitV2 {
            gateway: gateway.clone(),
        });

        let mut client_builder = Client::builder()
            .await
            .map_err(AdminGatewayError::ClientCreationError)?
            .with_iroh_enable_dht(true)
            .with_iroh_enable_next(true);
        client_builder.with_module_inits(registry);
        Ok(client_builder)
    }

    /// Recovers a client with the provided mnemonic. This function will wait
    /// for the recoveries to finish, but a new client must be created
    /// afterwards and waited on until the state machines have finished
    /// for a balance to be present.
    pub async fn recover(
        &self,
        config: FederationConfig,
        gateway: Arc<Gateway>,
        mnemonic: &Mnemonic,
    ) -> AdminResult<()> {
        let federation_id = config.invite_code.federation_id();
        let db = gateway.gateway_db.get_client_database(&federation_id);
        let client_builder = self.create_client_builder(&config, gateway.clone()).await?;
        let root_secret = RootSecret::StandardDoubleDerive(
            Bip39RootSecretStrategy::<12>::to_root_secret(mnemonic),
        );
        let client = client_builder
            .preview(self.connectors.clone(), &config.invite_code)
            .await?
            .recover(db, root_secret, None)
            .await
            .map(Arc::new)
            .map_err(AdminGatewayError::ClientCreationError)?;
        client
            .wait_for_all_recoveries()
            .await
            .map_err(AdminGatewayError::ClientCreationError)?;
        Ok(())
    }

    /// Builds a new client with the provided `FederationConfig` and `Mnemonic`.
    /// Only used for newly joined federations.
    pub async fn build(
        &self,
        config: FederationConfig,
        gateway: Arc<Gateway>,
        mnemonic: &Mnemonic,
    ) -> AdminResult<fedimint_client::ClientHandleArc> {
        let invite_code = config.invite_code.clone();
        let federation_id = invite_code.federation_id();
        let db_path = self.work_dir.join(format!("{federation_id}.db"));

        let (db, root_secret) = if db_path.exists() {
            let db = match self.db_backend {
                DatabaseBackend::RocksDb => {
                    let rocksdb = fedimint_rocksdb::RocksDb::build(db_path.clone())
                        .open()
                        .await
                        .map_err(AdminGatewayError::ClientCreationError)?;
                    Database::new(rocksdb, ModuleDecoderRegistry::default())
                }
                DatabaseBackend::CursedRedb => {
                    let cursed_redb = fedimint_cursed_redb::MemAndRedb::new(db_path.clone())
                        .await
                        .map_err(AdminGatewayError::ClientCreationError)?;
                    Database::new(cursed_redb, ModuleDecoderRegistry::default())
                }
            };
            let root_secret = RootSecret::Custom(self.client_plainrootsecret(&db).await?);
            (db, root_secret)
        } else {
            let db = gateway.gateway_db.get_client_database(&federation_id);

            let root_secret = RootSecret::StandardDoubleDerive(
                Bip39RootSecretStrategy::<12>::to_root_secret(mnemonic),
            );
            (db, root_secret)
        };

        Self::verify_client_config(&db, federation_id).await?;

        let client_builder = self.create_client_builder(&config, gateway).await?;

        if Client::is_initialized(&db).await {
            client_builder
                .open(self.connectors.clone(), db, root_secret)
                .await
        } else {
            client_builder
                .preview(self.connectors.clone(), &invite_code)
                .await?
                .join(db, root_secret)
                .await
        }
        .map(Arc::new)
        .map_err(AdminGatewayError::ClientCreationError)
    }

    /// Verifies that the saved `ClientConfig` contains the expected
    /// federation's config.
    async fn verify_client_config(db: &Database, federation_id: FederationId) -> AdminResult<()> {
        let mut dbtx = db.begin_read_transaction().await;
        if let Some(config) = dbtx.get_value(&ClientConfigKey).await
            && config.calculate_federation_id() != federation_id
        {
            return Err(AdminGatewayError::ClientCreationError(anyhow::anyhow!(
                "Federation Id did not match saved federation ID".to_string()
            )));
        }
        Ok(())
    }

    /// Returns a vector of "legacy" federations which did not derive their
    /// client secret's from the gateway's mnemonic.
    pub fn legacy_federations(&self, all_federations: BTreeSet<FederationId>) -> Vec<FederationId> {
        all_federations
            .into_iter()
            .filter(|federation_id| {
                let db_path = self.work_dir.join(format!("{federation_id}.db"));
                db_path.exists()
            })
            .collect::<Vec<FederationId>>()
    }
}
