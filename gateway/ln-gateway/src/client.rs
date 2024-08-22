use std::collections::BTreeSet;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use bip39::Mnemonic;
use fedimint_bip39::Bip39RootSecretStrategy;
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{Client, ClientBuilder};
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use rand::thread_rng;
use tracing::info;

use crate::db::FederationConfig;
use crate::gateway_module_v2::GatewayClientInitV2;
use crate::state_machine::GatewayClientInit;
use crate::{Gateway, GatewayError, Result};

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

    async fn client_plainrootsecret(&self, db: &Database) -> Result<DerivableSecret> {
        let client_secret =
            if let Ok(secret) = Client::load_decodable_client_secret::<[u8; 64]>(db).await {
                secret
            } else {
                info!("Generating secret and writing to client storage");
                let secret = PlainRootSecretStrategy::random(&mut thread_rng());
                Client::store_encodable_client_secret(db, secret)
                    .await
                    .map_err(GatewayError::ClientStateMachineError)?;
                secret
            };

        Ok(PlainRootSecretStrategy::to_root_secret(&client_secret))
    }

    async fn create_client_builder(
        &self,
        db: Database,
        federation_config: &FederationConfig,
        gateway: Arc<Gateway>,
    ) -> Result<ClientBuilder> {
        let FederationConfig {
            mint_channel_id,
            timelock_delta,
            connector,
            ..
        } = federation_config.to_owned();

        let mut registry = self.registry.clone();

        registry.attach(GatewayClientInit {
            timelock_delta,
            mint_channel_id,
            gateway: gateway.clone(),
        });
        registry.attach(GatewayClientInitV2 {
            gateway: gateway.clone(),
        });

        let mut client_builder = Client::builder(db)
            .await
            .map_err(GatewayError::DatabaseError)?;
        client_builder.with_module_inits(registry);
        client_builder.with_primary_module(self.primary_module);
        client_builder.with_connector(connector);
        Ok(client_builder)
    }

    pub async fn build(
        &self,
        config: FederationConfig,
        gateway: Arc<Gateway>,
        mnemonic: &Mnemonic,
    ) -> Result<fedimint_client::ClientHandleArc> {
        let invite_code = config.invite_code.clone();
        let federation_id = invite_code.federation_id();
        let db_path = self.work_dir.join(format!("{federation_id}.db"));

        let (db, root_secret) = if db_path.exists() {
            let rocksdb = fedimint_rocksdb::RocksDb::open(db_path.clone()).map_err(|e| {
                GatewayError::DatabaseError(anyhow::anyhow!("Error opening rocksdb: {e:?}"))
            })?;
            let db = Database::new(rocksdb, ModuleDecoderRegistry::default());
            let root_secret = self.client_plainrootsecret(&db).await?;
            (db, root_secret)
        } else {
            let db = gateway
                .gateway_db
                .with_prefix(federation_id.to_prefix().as_bytes());
            let root_secret = Bip39RootSecretStrategy::<12>::to_root_secret(mnemonic);
            (db, root_secret)
        };

        let client_builder = self.create_client_builder(db, &config, gateway).await?;

        if Client::is_initialized(client_builder.db_no_decoders()).await {
            client_builder.open(root_secret).await
        } else {
            let client_config = config
                .connector
                .download_from_invite_code(&invite_code)
                .await?;
            client_builder
                .join(root_secret, client_config.clone(), invite_code.api_secret())
                .await
        }
        .map(Arc::new)
        .map_err(GatewayError::ClientStateMachineError)
    }

    pub fn legacy_federations(&self, all_federations: BTreeSet<FederationId>) -> Vec<FederationId> {
        let mut legacy_federations = Vec::new();
        for federation_id in all_federations {
            let db_path = self.work_dir.join(format!("{federation_id}.db"));
            if db_path.exists() {
                legacy_federations.push(federation_id);
            }
        }

        legacy_federations
    }
}
