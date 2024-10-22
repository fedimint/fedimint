use std::collections::BTreeMap;

use bitcoin::Network;
use bitcoin_hashes::sha256;
use fedimint_api_client::api::net::Connector;
use fedimint_core::config::FederationId;
use fedimint_core::db::{
    CoreMigrationFn, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::{impl_db_lookup, impl_db_record, push_db_pair_items, secp256k1, Amount};
use fedimint_ln_common::serde_routing_fees;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use futures::{FutureExt, StreamExt};
use lightning_invoice::RoutingFees;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{Keypair, Secp256k1};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::rpc::rpc_server::hash_password;

pub trait GatewayDbtxNcExt {
    async fn save_federation_config(&mut self, config: &FederationConfig);
    async fn load_federation_configs_v0(&mut self) -> BTreeMap<FederationId, FederationConfigV0>;
    async fn load_federation_configs(&mut self) -> BTreeMap<FederationId, FederationConfig>;
    async fn load_federation_config(
        &mut self,
        federation_id: FederationId,
    ) -> Option<FederationConfig>;
    async fn remove_federation_config(&mut self, federation_id: FederationId);

    /// Returns the keypair that uniquely identifies the gateway.
    async fn load_gateway_keypair(&mut self) -> Option<Keypair>;

    /// Returns the keypair that uniquely identifies the gateway.
    ///
    /// # Panics
    /// Gateway keypair does not exist.
    async fn load_gateway_keypair_assert_exists(&mut self) -> Keypair;

    /// Returns the keypair that uniquely identifies the gateway, creating it if
    /// it does not exist. Remember to commit the transaction after calling this
    /// method.
    async fn load_or_create_gateway_keypair(&mut self) -> Keypair;

    async fn load_gateway_config(&mut self) -> Option<GatewayConfiguration>;

    async fn set_gateway_config(&mut self, gateway_config: &GatewayConfiguration);

    async fn save_new_preimage_authentication(
        &mut self,
        payment_hash: sha256::Hash,
        preimage_auth: sha256::Hash,
    );

    async fn load_preimage_authentication(
        &mut self,
        payment_hash: sha256::Hash,
    ) -> Option<sha256::Hash>;

    /// Saves a registered incoming contract, returning the previous contract
    /// with the same payment hash if it existed.
    async fn save_registered_incoming_contract(
        &mut self,
        federation_id: FederationId,
        incoming_amount: Amount,
        contract: IncomingContract,
    ) -> Option<RegisteredIncomingContract>;

    async fn load_registered_incoming_contract(
        &mut self,
        payment_image: PaymentImage,
    ) -> Option<RegisteredIncomingContract>;

    /// Reads and serializes structures from the gateway's database for the
    /// purpose for serializing to JSON for inspection.
    async fn dump_database(
        &mut self,
        prefix_names: Vec<String>,
    ) -> BTreeMap<String, Box<dyn erased_serde::Serialize + Send>>;
}

impl<Cap: Send> GatewayDbtxNcExt for DatabaseTransaction<'_, Cap> {
    async fn save_federation_config(&mut self, config: &FederationConfig) {
        let id = config.invite_code.federation_id();
        self.insert_entry(&FederationIdKey { id }, config).await;
    }

    async fn load_federation_configs_v0(&mut self) -> BTreeMap<FederationId, FederationConfigV0> {
        self.find_by_prefix(&FederationIdKeyPrefixV0)
            .await
            .map(|(key, config): (FederationIdKeyV0, FederationConfigV0)| (key.id, config))
            .collect::<BTreeMap<FederationId, FederationConfigV0>>()
            .await
    }

    async fn load_federation_configs(&mut self) -> BTreeMap<FederationId, FederationConfig> {
        self.find_by_prefix(&FederationIdKeyPrefix)
            .await
            .map(|(key, config): (FederationIdKey, FederationConfig)| (key.id, config))
            .collect::<BTreeMap<FederationId, FederationConfig>>()
            .await
    }

    async fn load_federation_config(
        &mut self,
        federation_id: FederationId,
    ) -> Option<FederationConfig> {
        self.get_value(&FederationIdKey { id: federation_id }).await
    }

    async fn remove_federation_config(&mut self, federation_id: FederationId) {
        self.remove_entry(&FederationIdKey { id: federation_id })
            .await;
    }

    async fn load_gateway_keypair(&mut self) -> Option<Keypair> {
        self.get_value(&GatewayPublicKey).await
    }

    async fn load_gateway_keypair_assert_exists(&mut self) -> Keypair {
        self.get_value(&GatewayPublicKey)
            .await
            .expect("Gateway keypair does not exist")
    }

    async fn load_or_create_gateway_keypair(&mut self) -> Keypair {
        if let Some(key_pair) = self.get_value(&GatewayPublicKey).await {
            key_pair
        } else {
            let context = Secp256k1::new();
            let (secret_key, _public_key) = context.generate_keypair(&mut OsRng);
            let key_pair = Keypair::from_secret_key(&context, &secret_key);
            self.insert_new_entry(&GatewayPublicKey, &key_pair).await;
            key_pair
        }
    }

    async fn load_gateway_config(&mut self) -> Option<GatewayConfiguration> {
        self.get_value(&GatewayConfigurationKey).await
    }

    async fn set_gateway_config(&mut self, gateway_config: &GatewayConfiguration) {
        self.insert_entry(&GatewayConfigurationKey, gateway_config)
            .await;
    }

    async fn save_new_preimage_authentication(
        &mut self,
        payment_hash: sha256::Hash,
        preimage_auth: sha256::Hash,
    ) {
        self.insert_new_entry(&PreimageAuthentication { payment_hash }, &preimage_auth)
            .await;
    }

    async fn load_preimage_authentication(
        &mut self,
        payment_hash: sha256::Hash,
    ) -> Option<sha256::Hash> {
        self.get_value(&PreimageAuthentication { payment_hash })
            .await
    }

    async fn save_registered_incoming_contract(
        &mut self,
        federation_id: FederationId,
        incoming_amount: Amount,
        contract: IncomingContract,
    ) -> Option<RegisteredIncomingContract> {
        self.insert_entry(
            &RegisteredIncomingContractKey(contract.commitment.payment_image.clone()),
            &RegisteredIncomingContract {
                federation_id,
                incoming_amount_msats: incoming_amount.msats,
                contract,
            },
        )
        .await
    }

    async fn load_registered_incoming_contract(
        &mut self,
        payment_image: PaymentImage,
    ) -> Option<RegisteredIncomingContract> {
        self.get_value(&RegisteredIncomingContractKey(payment_image))
            .await
    }

    async fn dump_database(
        &mut self,
        prefix_names: Vec<String>,
    ) -> BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> {
        let mut gateway_items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::FederationConfig => {
                    push_db_pair_items!(
                        self,
                        FederationIdKeyPrefix,
                        FederationIdKey,
                        FederationConfig,
                        gateway_items,
                        "Federation Config"
                    );
                }
                DbKeyPrefix::GatewayConfiguration => {
                    if let Some(gateway_config) = self.load_gateway_config().await {
                        gateway_items.insert(
                            "Gateway Configuration".to_string(),
                            Box::new(gateway_config),
                        );
                    }
                }
                DbKeyPrefix::GatewayPublicKey => {
                    if let Some(public_key) = self.load_gateway_keypair().await {
                        gateway_items
                            .insert("Gateway Public Key".to_string(), Box::new(public_key));
                    }
                }
                _ => {}
            }
        }

        gateway_items
    }
}

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
enum DbKeyPrefix {
    FederationConfig = 0x04,
    GatewayPublicKey = 0x06,
    GatewayConfiguration = 0x07,
    PreimageAuthentication = 0x08,
    RegisteredIncomingContract = 0x09,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable)]
struct FederationIdKeyPrefixV0;

#[derive(Debug, Encodable, Decodable)]
struct FederationIdKeyPrefix;

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct FederationIdKeyV0 {
    id: FederationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct FederationConfigV0 {
    pub invite_code: InviteCode,
    pub federation_index: u64,
    pub timelock_delta: u64,
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct FederationIdKey {
    id: FederationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct FederationConfig {
    pub invite_code: InviteCode,
    // Unique integer identifier per-federation that is assigned when the gateways joins a
    // federation.
    #[serde(alias = "mint_channel_id")]
    pub federation_index: u64,
    pub timelock_delta: u64,
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
    pub connector: Connector,
}

impl_db_record!(
    key = FederationIdKeyV0,
    value = FederationConfigV0,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_record!(
    key = FederationIdKey,
    value = FederationConfig,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_lookup!(
    key = FederationIdKeyV0,
    query_prefix = FederationIdKeyPrefixV0
);
impl_db_lookup!(key = FederationIdKey, query_prefix = FederationIdKeyPrefix);

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
struct GatewayPublicKey;

impl_db_record!(
    key = GatewayPublicKey,
    value = Keypair,
    db_prefix = DbKeyPrefix::GatewayPublicKey,
);

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
struct GatewayConfigurationKeyV0;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
struct GatewayConfigurationV0 {
    password: String,
    num_route_hints: u32,
    #[serde(with = "serde_routing_fees")]
    routing_fees: RoutingFees,
    network: Network,
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct GatewayConfigurationKey;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct GatewayConfiguration {
    pub hashed_password: sha256::Hash,
    pub num_route_hints: u32,
    #[serde(with = "serde_routing_fees")]
    pub routing_fees: RoutingFees,
    pub network: Network,
    pub password_salt: [u8; 16],
}

impl_db_record!(
    key = GatewayConfigurationKeyV0,
    value = GatewayConfigurationV0,
    db_prefix = DbKeyPrefix::GatewayConfiguration,
);

impl_db_record!(
    key = GatewayConfigurationKey,
    value = GatewayConfiguration,
    db_prefix = DbKeyPrefix::GatewayConfiguration,
    notify_on_modify = true,
);

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
struct PreimageAuthentication {
    payment_hash: sha256::Hash,
}

impl_db_record!(
    key = PreimageAuthentication,
    value = sha256::Hash,
    db_prefix = DbKeyPrefix::PreimageAuthentication
);

#[derive(Debug, Encodable, Decodable)]
struct PreimageAuthenticationPrefix;

impl_db_lookup!(
    key = PreimageAuthentication,
    query_prefix = PreimageAuthenticationPrefix
);

pub fn get_gatewayd_database_migrations() -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
    let mut migrations: BTreeMap<DatabaseVersion, CoreMigrationFn> = BTreeMap::new();
    migrations.insert(DatabaseVersion(0), |dbtx| migrate_to_v1(dbtx).boxed());
    migrations.insert(DatabaseVersion(1), |dbtx| migrate_to_v2(dbtx).boxed());
    migrations
}

async fn migrate_to_v1(dbtx: &mut DatabaseTransaction<'_>) -> Result<(), anyhow::Error> {
    // If there is no old gateway configuration, there is nothing to do.
    if let Some(old_gateway_config) = dbtx.remove_entry(&GatewayConfigurationKeyV0).await {
        let password_salt: [u8; 16] = rand::thread_rng().gen();
        let hashed_password = hash_password(&old_gateway_config.password, password_salt);
        let new_gateway_config = GatewayConfiguration {
            hashed_password,
            num_route_hints: old_gateway_config.num_route_hints,
            routing_fees: old_gateway_config.routing_fees,
            network: old_gateway_config.network,
            password_salt,
        };
        dbtx.insert_entry(&GatewayConfigurationKey, &new_gateway_config)
            .await;
    }

    Ok(())
}

async fn migrate_to_v2(dbtx: &mut DatabaseTransaction<'_>) -> Result<(), anyhow::Error> {
    // If there is no old federation configuration, there is nothing to do.
    for (old_federation_id, _old_federation_config) in dbtx.load_federation_configs_v0().await {
        if let Some(old_federation_config) = dbtx
            .remove_entry(&FederationIdKeyV0 {
                id: old_federation_id,
            })
            .await
        {
            let new_federation_config = FederationConfig {
                invite_code: old_federation_config.invite_code,
                federation_index: old_federation_config.federation_index,
                timelock_delta: old_federation_config.timelock_delta,
                fees: old_federation_config.fees,
                connector: Connector::default(),
            };
            let new_federation_key = FederationIdKey {
                id: old_federation_id,
            };
            dbtx.insert_entry(&new_federation_key, &new_federation_config)
                .await;
        }
    }
    Ok(())
}

#[derive(Debug, Encodable, Decodable)]
struct RegisteredIncomingContractKey(pub PaymentImage);

#[derive(Debug, Encodable, Decodable)]
pub struct RegisteredIncomingContract {
    pub federation_id: FederationId,
    /// The amount of the incoming contract, in msats.
    pub incoming_amount_msats: u64,
    pub contract: IncomingContract,
}

impl_db_record!(
    key = RegisteredIncomingContractKey,
    value = RegisteredIncomingContract,
    db_prefix = DbKeyPrefix::RegisteredIncomingContract,
);

#[cfg(test)]
mod fedimint_migration_tests {
    use std::str::FromStr;

    use anyhow::ensure;
    use bitcoin_hashes::Hash;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::util::SafeUrl;
    use fedimint_logging::TracingSetup;
    use fedimint_testing::db::{
        snapshot_db_migrations_with_decoders, validate_migrations_global, BYTE_32,
    };
    use strum::IntoEnumIterator;
    use tracing::info;

    use super::*;
    use crate::DEFAULT_FEES;

    async fn create_gatewayd_db_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;
        let federation_id = FederationId::dummy();
        let invite_code = InviteCode::new(
            SafeUrl::from_str("http://myexamplefed.com").expect("SafeUrl parsing can't fail"),
            0.into(),
            federation_id,
            None,
        );
        let federation_config = FederationConfigV0 {
            invite_code,
            federation_index: 2,
            timelock_delta: 10,
            fees: DEFAULT_FEES,
        };

        dbtx.insert_new_entry(&FederationIdKeyV0 { id: federation_id }, &federation_config)
            .await;

        let context = secp256k1::Secp256k1::new();
        let (secret, _) = context.generate_keypair(&mut OsRng);
        let key_pair = secp256k1::Keypair::from_secret_key(&context, &secret);
        dbtx.insert_new_entry(&GatewayPublicKey, &key_pair).await;

        let gateway_configuration = GatewayConfigurationV0 {
            password: "EXAMPLE".to_string(),
            num_route_hints: 2,
            routing_fees: DEFAULT_FEES,
            network: Network::Regtest,
        };

        dbtx.insert_new_entry(&GatewayConfigurationKeyV0, &gateway_configuration)
            .await;

        let preimage_auth = PreimageAuthentication {
            payment_hash: sha256::Hash::from_slice(&BYTE_32).expect("Hash should not fail"),
        };
        let verification_hash = sha256::Hash::from_slice(&BYTE_32).expect("Hash should not fail");
        dbtx.insert_new_entry(&preimage_auth, &verification_hash)
            .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_with_decoders(
            "gatewayd",
            |db| {
                Box::pin(async {
                    create_gatewayd_db_data(db).await;
                })
            },
            ModuleDecoderRegistry::from_iter([]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();
        validate_migrations_global(
            |db| async move {
                let mut dbtx = db.begin_transaction_nc().await;

                for prefix in DbKeyPrefix::iter() {
                    match prefix {
                        DbKeyPrefix::FederationConfig => {
                            let configs = dbtx
                                .find_by_prefix(&FederationIdKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_configs = configs.len();
                            ensure!(
                                num_configs > 0,
                                "validate_migrations was not able to read any FederationConfigs"
                            );
                            info!("Validated FederationConfig");
                        }
                        DbKeyPrefix::GatewayPublicKey => {
                            let gateway_id = dbtx.get_value(&GatewayPublicKey).await;
                            ensure!(gateway_id.is_some(), "validate_migrations was not able to read GatewayPublicKey");
                            info!("Validated GatewayPublicKey");
                        }
                        DbKeyPrefix::PreimageAuthentication => {
                            let preimage_authentications = dbtx.find_by_prefix(&PreimageAuthenticationPrefix).await.collect::<Vec<_>>().await;
                            let num_auths = preimage_authentications.len();
                            ensure!(num_auths > 0, "validate_migrations was not able to read any PreimageAuthentication");
                            info!("Validated PreimageAuthentication");
                        }
                        DbKeyPrefix::GatewayConfiguration => {
                            let gateway_configuration = dbtx.get_value(&GatewayConfigurationKey).await;
                            ensure!(gateway_configuration.is_some(), "validate_migrations was not able to read GatewayConfiguration");
                            info!("Validated GatewayConfiguration");
                        }
                        DbKeyPrefix::RegisteredIncomingContract => {}
                    }
                }
                Ok(())
            },
            "gatewayd",
            get_gatewayd_database_migrations(),
            ModuleDecoderRegistry::from_iter([]),
        )
        .await
    }
}
