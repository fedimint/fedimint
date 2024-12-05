use std::collections::BTreeSet;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::db::ClientConfigKey;
use fedimint_client::derivable_secret::{ChildId, DerivableSecret};
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{Client, ClientBuilder};
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;

use crate::db::FederationConfig;
use crate::error::AdminGatewayError;
use crate::gateway_module_v2::GatewayClientInitV2;
use crate::state_machine::GatewayClientInit;
use crate::{AdminResult, Gateway};

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
        db: Database,
        federation_config: &FederationConfig,
        gateway: Arc<Gateway>,
    ) -> AdminResult<ClientBuilder> {
        let FederationConfig {
            federation_index,
            timelock_delta,
            connector,
            ..
        } = federation_config.to_owned();

        let mut registry = self.registry.clone();

        if gateway.is_running_lnv1() {
            registry.attach(GatewayClientInit {
                timelock_delta,
                federation_index,
                gateway: gateway.clone(),
            });
        }

        if gateway.is_running_lnv2() {
            registry.attach(GatewayClientInitV2 {
                gateway: gateway.clone(),
            });
        }

        let mut client_builder = Client::builder(db)
            .await
            .map_err(AdminGatewayError::ClientCreationError)?;
        client_builder.with_module_inits(registry);
        client_builder.with_primary_module(self.primary_module);
        client_builder.with_connector(connector);
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
        let client_config = config
            .connector
            .download_from_invite_code(&config.invite_code)
            .await
            .map_err(AdminGatewayError::ClientCreationError)?;
        let federation_id = config.invite_code.federation_id();
        let db = gateway
            .gateway_db
            .with_prefix(federation_id.consensus_encode_to_vec());
        let client_builder = self
            .create_client_builder(db, &config, gateway.clone())
            .await?;
        let secret = Self::derive_federation_secret(mnemonic, &federation_id);
        let backup = client_builder
            .download_backup_from_federation(
                &secret,
                &client_config,
                config.invite_code.api_secret(),
            )
            .await
            .map_err(AdminGatewayError::ClientCreationError)?;
        let client = client_builder
            .recover(
                secret.clone(),
                client_config,
                config.invite_code.api_secret(),
                backup,
            )
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
    ) -> AdminResult<fedimint_client::ClientHandle> {
        let invite_code = config.invite_code.clone();
        let federation_id = invite_code.federation_id();
        let db_path = self.work_dir.join(format!("{federation_id}.db"));

        let (db, root_secret) = if db_path.exists() {
            let rocksdb = fedimint_rocksdb::RocksDb::open(db_path.clone())
                .map_err(AdminGatewayError::ClientCreationError)?;
            let db = Database::new(rocksdb, ModuleDecoderRegistry::default());
            let root_secret = self.client_plainrootsecret(&db).await?;
            (db, root_secret)
        } else {
            let db = gateway
                .gateway_db
                .with_prefix(federation_id.consensus_encode_to_vec());
            let secret = Self::derive_federation_secret(mnemonic, &federation_id);
            (db, secret)
        };

        Self::verify_client_config(&db, federation_id).await?;

        let client_builder = self.create_client_builder(db, &config, gateway).await?;

        if Client::is_initialized(client_builder.db_no_decoders()).await {
            client_builder.open(root_secret).await
        } else {
            let client_config = config
                .connector
                .download_from_invite_code(&invite_code)
                .await
                .map_err(AdminGatewayError::ClientCreationError)?;
            client_builder
                .join(root_secret, client_config.clone(), invite_code.api_secret())
                .await
        }
        .map_err(AdminGatewayError::ClientCreationError)
    }

    /// Verifies that the saved `ClientConfig` contains the expected
    /// federation's config.
    async fn verify_client_config(db: &Database, federation_id: FederationId) -> AdminResult<()> {
        let mut dbtx = db.begin_transaction_nc().await;
        if let Some(config) = dbtx.get_value(&ClientConfigKey).await {
            if config.calculate_federation_id() != federation_id {
                return Err(AdminGatewayError::ClientCreationError(anyhow::anyhow!(
                    "Federation Id did not match saved federation ID".to_string()
                )));
            }
        }
        Ok(())
    }

    /// Derives a per-federation secret according to Fedimint's multi-federation
    /// secret derivation policy.
    fn derive_federation_secret(
        mnemonic: &Mnemonic,
        federation_id: &FederationId,
    ) -> DerivableSecret {
        let global_root_secret = Bip39RootSecretStrategy::<12>::to_root_secret(mnemonic);
        let multi_federation_root_secret = global_root_secret.child_key(ChildId(0));
        let federation_root_secret = multi_federation_root_secret.federation_key(federation_id);
        let federation_wallet_root_secret = federation_root_secret.child_key(ChildId(0));
        federation_wallet_root_secret.child_key(ChildId(0))
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
