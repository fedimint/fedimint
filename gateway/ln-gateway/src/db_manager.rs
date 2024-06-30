use std::collections::BTreeMap;

use fedimint_core::db::{apply_migrations_server, Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::secp256k1::{KeyPair, PublicKey, Secp256k1};
use fedimint_ln_common::config::GatewayFee;
use futures::stream::StreamExt;
use rand::rngs::OsRng;
use rand::Rng;

use crate::db::{
    get_gatewayd_database_migrations, FederationConfig, FederationIdKey, FederationIdKeyPrefix,
    GatewayConfiguration, GatewayConfigurationKey, GatewayPublicKey, GATEWAYD_DATABASE_VERSION,
};
use crate::rpc::rpc_server::hash_password;
use crate::{GatewayError, GatewayParameters, Result, DEFAULT_FEES, DEFAULT_NETWORK};

#[derive(Clone, Debug)]
pub struct DbManager {
    /// Database for Gateway metadata.
    pub gateway_db: Database,
}

impl DbManager {
    pub async fn new(gateway_db: Database) -> Result<Self> {
        // Apply database migrations before using the database to ensure old database
        // structures are readable.
        apply_migrations_server(
            &gateway_db,
            "gatewayd".to_string(),
            GATEWAYD_DATABASE_VERSION,
            get_gatewayd_database_migrations(),
        )
        .await?;

        Ok(Self { gateway_db })
    }

    pub async fn save_config(&self, config: &FederationConfig) -> Result<()> {
        let mut dbtx = self.gateway_db.begin_transaction().await;
        let id = config.invite_code.federation_id();
        dbtx.insert_entry(&FederationIdKey { id }, config).await;
        dbtx.commit_tx_result()
            .await
            .map_err(GatewayError::DatabaseError)
    }

    pub async fn load_configs(&self) -> Vec<FederationConfig> {
        self.gateway_db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&FederationIdKeyPrefix)
            .await
            .collect::<BTreeMap<FederationIdKey, FederationConfig>>()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>()
    }

    /// This function will return a `GatewayConfiguration` one of two
    /// ways. To avoid conflicting configs, the below order is the
    /// order in which the gateway will respect configurations:
    /// - `GatewayConfiguration` is read from the database.
    /// - All cli or environment variables are set such that we can create a
    ///   `GatewayConfiguration`
    pub async fn get_gateway_config(
        &self,
        gateway_parameters: &GatewayParameters,
    ) -> Option<GatewayConfiguration> {
        let mut dbtx = self.gateway_db.begin_transaction_nc().await;

        // Always use the gateway configuration from the database if it exists.
        if let Some(gateway_config) = dbtx.get_value(&GatewayConfigurationKey).await {
            return Some(gateway_config);
        }

        // If the password is not provided, return None
        let password = gateway_parameters.password.as_ref()?;

        // If the DB does not have the gateway configuration, we can construct one from
        // the provided password (required) and the defaults.
        // Use gateway parameters provided by the environment or CLI
        let num_route_hints = gateway_parameters.num_route_hints;
        let routing_fees = gateway_parameters
            .fees
            .clone()
            .unwrap_or(GatewayFee(DEFAULT_FEES));
        let network = gateway_parameters.network.unwrap_or(DEFAULT_NETWORK);
        let password_salt: [u8; 16] = rand::thread_rng().gen();
        let hashed_password = hash_password(password, password_salt);
        let gateway_config = GatewayConfiguration {
            hashed_password,
            network,
            num_route_hints,
            routing_fees: routing_fees.0,
            password_salt,
        };

        Some(gateway_config)
    }

    /// Returns a `PublicKey` that uniquely identifies the Gateway.
    pub async fn load_gateway_id(&self) -> PublicKey {
        let mut dbtx = self.gateway_db.begin_transaction().await;
        if let Some(key_pair) = dbtx.get_value(&GatewayPublicKey {}).await {
            key_pair.public_key()
        } else {
            let context = Secp256k1::new();
            let (secret, public) = context.generate_keypair(&mut OsRng);
            let key_pair = KeyPair::from_secret_key(&context, &secret);
            dbtx.insert_new_entry(&GatewayPublicKey, &key_pair).await;
            dbtx.commit_tx().await;
            public
        }
    }

    /// Returns the gateway's stored configuration, waiting until it exists if
    /// it doesn't yet.
    pub async fn get_gateway_config_wait_until_exists(&self) -> GatewayConfiguration {
        self.gateway_db
            .wait_key_exists(&GatewayConfigurationKey)
            .await
    }
}
