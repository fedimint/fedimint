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
use fedimint_core::db::{
    Database, IRawDatabase, IReadDatabaseTransactionOps, IReadDatabaseTransactionOpsTyped,
    IWriteDatabaseTransactionOps,
};
use fedimint_derive_secret::DerivableSecret;
use fedimint_gateway_common::FederationConfig;
use fedimint_gateway_server_db::GatewayDbExt as _;
use fedimint_gw_client::GatewayClientInit;
use fedimint_gwv2_client::GatewayClientInitV2;
use tracing::info;

use crate::error::AdminGatewayError;
use crate::{AdminResult, Gateway, LOG_GATEWAY};

#[derive(Debug, Clone)]
pub struct GatewayClientBuilder {
    work_dir: PathBuf,
    registry: ClientModuleInitRegistry,
    connectors: ConnectorRegistry,
}

impl GatewayClientBuilder {
    pub async fn new(
        work_dir: PathBuf,
        registry: ClientModuleInitRegistry,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            connectors: ConnectorRegistry::build_from_client_env()?.bind().await?,
            work_dir,
            registry,
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

        // Check for legacy per-federation database (pre-v0.5.0)
        // If it exists, migrate it to the prefixed gateway database
        let legacy_db_path = self.work_dir.join(format!("{federation_id}.db"));
        let (db, root_secret) = if legacy_db_path.exists() {
            // Migrate legacy database to prefixed gateway database
            self.migrate_legacy_federation_database(&gateway.gateway_db, &federation_id)
                .await
                .map_err(AdminGatewayError::ClientCreationError)?;

            // Now load from the prefixed database and use the legacy root secret
            let db = gateway.gateway_db.get_client_database(&federation_id);
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

    /// Migrates a legacy per-federation RocksDB database into the main gateway
    /// database as a prefixed sub-database.
    async fn migrate_legacy_federation_database(
        &self,
        gateway_db: &Database,
        federation_id: &FederationId,
    ) -> anyhow::Result<()> {
        use futures::StreamExt;

        let legacy_path = self.work_dir.join(format!("{federation_id}.db"));
        let target_db = gateway_db.get_client_database(federation_id);

        if legacy_path.is_dir() {
            // It's RocksDB - migrate to prefixed gateway database
            info!(
                target: LOG_GATEWAY,
                %federation_id,
                "Migrating legacy federation database to gateway database..."
            );

            let rocksdb = fedimint_rocksdb::RocksDb::build(&legacy_path)
                .open()
                .await?;

            // Copy all data from legacy database to prefixed gateway database
            let mut read_tx = rocksdb.begin_read_transaction().await;
            let mut write_tx = target_db.begin_write_transaction().await;

            let mut entries = read_tx.raw_find_by_prefix(&[]).await?;
            while let Some((key, value)) = entries.next().await {
                write_tx.raw_insert_bytes(&key, &value).await?;
            }
            drop(entries);
            drop(read_tx);
            write_tx.commit_tx().await;

            drop(rocksdb);
        } else {
            // It's already redb at legacy path - migrate to prefixed gateway database
            info!(
                target: LOG_GATEWAY,
                %federation_id,
                "Migrating legacy redb federation database to gateway database..."
            );

            let redb = fedimint_redb::RedbDatabase::open(&legacy_path)?;

            // Copy all data from legacy database to prefixed gateway database
            let mut read_tx = redb.begin_read_transaction().await;
            let mut write_tx = target_db.begin_write_transaction().await;

            let mut entries = read_tx.raw_find_by_prefix(&[]).await?;
            while let Some((key, value)) = entries.next().await {
                write_tx.raw_insert_bytes(&key, &value).await?;
            }
            drop(entries);
            drop(read_tx);
            write_tx.commit_tx().await;

            drop(redb);
        }

        std::fs::rename(
            &legacy_path,
            self.work_dir.join(format!("{federation_id}.db.migrated")),
        )?;

        info!(
            target: LOG_GATEWAY,
            %federation_id,
            "Legacy federation database migration complete"
        );

        Ok(())
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
