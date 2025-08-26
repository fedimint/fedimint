#![allow(clippy::collapsible_if)]

use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use fedimint_api_client::api::net::Connector;
use fedimint_core::config::FederationId;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, GeneralDbMigrationFn,
    GeneralDbMigrationFnContext, IDatabaseTransactionOpsCore, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, impl_db_lookup, impl_db_record, push_db_pair_items, secp256k1};
use fedimint_gateway_common::FederationConfig;
use fedimint_ln_common::serde_routing_fees;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::PaymentFee;
use futures::{FutureExt, StreamExt};
use lightning_invoice::RoutingFees;
use rand::Rng;
use rand::rngs::OsRng;
use secp256k1::{Keypair, Secp256k1};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

pub trait GatewayDbExt {
    fn get_client_database(&self, federation_id: &FederationId) -> Database;
}

impl GatewayDbExt for Database {
    fn get_client_database(&self, federation_id: &FederationId) -> Database {
        let mut prefix = vec![DbKeyPrefix::ClientDatabase as u8];
        prefix.append(&mut federation_id.consensus_encode_to_vec());
        self.with_prefix(prefix)
    }
}

#[allow(async_fn_in_trait)]
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
        self.insert_entry(&FederationConfigKey { id }, config).await;
    }

    async fn load_federation_configs_v0(&mut self) -> BTreeMap<FederationId, FederationConfigV0> {
        self.find_by_prefix(&FederationConfigKeyPrefixV0)
            .await
            .map(|(key, config): (FederationConfigKeyV0, FederationConfigV0)| (key.id, config))
            .collect::<BTreeMap<FederationId, FederationConfigV0>>()
            .await
    }

    async fn load_federation_configs(&mut self) -> BTreeMap<FederationId, FederationConfig> {
        self.find_by_prefix(&FederationConfigKeyPrefix)
            .await
            .map(|(key, config): (FederationConfigKey, FederationConfig)| (key.id, config))
            .collect::<BTreeMap<FederationId, FederationConfig>>()
            .await
    }

    async fn load_federation_config(
        &mut self,
        federation_id: FederationId,
    ) -> Option<FederationConfig> {
        self.get_value(&FederationConfigKey { id: federation_id })
            .await
    }

    async fn remove_federation_config(&mut self, federation_id: FederationId) {
        self.remove_entry(&FederationConfigKey { id: federation_id })
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
                        FederationConfigKeyPrefix,
                        FederationConfigKey,
                        FederationConfig,
                        gateway_items,
                        "Federation Config"
                    );
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
    ClientDatabase = 0x10,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable)]
struct FederationConfigKeyPrefixV0;

#[derive(Debug, Encodable, Decodable)]
struct FederationConfigKeyPrefixV1;

#[derive(Debug, Encodable, Decodable)]
struct FederationConfigKeyPrefix;

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct FederationConfigKeyV0 {
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
struct FederationConfigKeyV1 {
    id: FederationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct FederationConfigV1 {
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

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct FederationConfigKey {
    id: FederationId,
}

impl_db_record!(
    key = FederationConfigKeyV0,
    value = FederationConfigV0,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_record!(
    key = FederationConfigKeyV1,
    value = FederationConfigV1,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_record!(
    key = FederationConfigKey,
    value = FederationConfig,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_lookup!(
    key = FederationConfigKeyV0,
    query_prefix = FederationConfigKeyPrefixV0
);
impl_db_lookup!(
    key = FederationConfigKeyV1,
    query_prefix = FederationConfigKeyPrefixV1
);
impl_db_lookup!(
    key = FederationConfigKey,
    query_prefix = FederationConfigKeyPrefix
);

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
    network: NetworkLegacyEncodingWrapper,
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct GatewayConfigurationKeyV1;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct GatewayConfigurationV1 {
    pub hashed_password: sha256::Hash,
    pub num_route_hints: u32,
    #[serde(with = "serde_routing_fees")]
    pub routing_fees: RoutingFees,
    pub network: NetworkLegacyEncodingWrapper,
    pub password_salt: [u8; 16],
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct GatewayConfigurationKeyV2;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct GatewayConfigurationV2 {
    pub num_route_hints: u32,
    #[serde(with = "serde_routing_fees")]
    pub routing_fees: RoutingFees,
    pub network: NetworkLegacyEncodingWrapper,
}

impl_db_record!(
    key = GatewayConfigurationKeyV0,
    value = GatewayConfigurationV0,
    db_prefix = DbKeyPrefix::GatewayConfiguration,
);

impl_db_record!(
    key = GatewayConfigurationKeyV1,
    value = GatewayConfigurationV1,
    db_prefix = DbKeyPrefix::GatewayConfiguration,
);

impl_db_record!(
    key = GatewayConfigurationKeyV2,
    value = GatewayConfigurationV2,
    db_prefix = DbKeyPrefix::GatewayConfiguration,
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

pub fn get_gatewayd_database_migrations() -> BTreeMap<DatabaseVersion, GeneralDbMigrationFn> {
    let mut migrations: BTreeMap<DatabaseVersion, GeneralDbMigrationFn> = BTreeMap::new();
    migrations.insert(
        DatabaseVersion(0),
        Box::new(|ctx| migrate_to_v1(ctx).boxed()),
    );
    migrations.insert(
        DatabaseVersion(1),
        Box::new(|ctx| migrate_to_v2(ctx).boxed()),
    );
    migrations.insert(
        DatabaseVersion(2),
        Box::new(|ctx| migrate_to_v3(ctx).boxed()),
    );
    migrations.insert(
        DatabaseVersion(3),
        Box::new(|ctx| migrate_to_v4(ctx).boxed()),
    );
    migrations.insert(
        DatabaseVersion(4),
        Box::new(|ctx| migrate_to_v5(ctx).boxed()),
    );
    migrations
}

async fn migrate_to_v1(mut ctx: GeneralDbMigrationFnContext<'_>) -> Result<(), anyhow::Error> {
    /// Creates a password hash by appending a 4 byte salt to the plaintext
    /// password.
    fn hash_password(plaintext_password: &str, salt: [u8; 16]) -> sha256::Hash {
        let mut bytes = Vec::new();
        bytes.append(&mut plaintext_password.consensus_encode_to_vec());
        bytes.append(&mut salt.consensus_encode_to_vec());
        sha256::Hash::hash(&bytes)
    }

    let mut dbtx = ctx.dbtx();

    // If there is no old gateway configuration, there is nothing to do.
    if let Some(old_gateway_config) = dbtx.remove_entry(&GatewayConfigurationKeyV0).await {
        let password_salt: [u8; 16] = rand::thread_rng().r#gen();
        let hashed_password = hash_password(&old_gateway_config.password, password_salt);
        let new_gateway_config = GatewayConfigurationV1 {
            hashed_password,
            num_route_hints: old_gateway_config.num_route_hints,
            routing_fees: old_gateway_config.routing_fees,
            network: old_gateway_config.network,
            password_salt,
        };
        dbtx.insert_entry(&GatewayConfigurationKeyV1, &new_gateway_config)
            .await;
    }

    Ok(())
}

async fn migrate_to_v2(mut ctx: GeneralDbMigrationFnContext<'_>) -> Result<(), anyhow::Error> {
    let mut dbtx = ctx.dbtx();

    // If there is no old federation configuration, there is nothing to do.
    for (old_federation_id, _old_federation_config) in dbtx.load_federation_configs_v0().await {
        if let Some(old_federation_config) = dbtx
            .remove_entry(&FederationConfigKeyV0 {
                id: old_federation_id,
            })
            .await
        {
            let new_federation_config = FederationConfigV1 {
                invite_code: old_federation_config.invite_code,
                federation_index: old_federation_config.federation_index,
                timelock_delta: old_federation_config.timelock_delta,
                fees: old_federation_config.fees,
                connector: Connector::default(),
            };
            let new_federation_key = FederationConfigKeyV1 {
                id: old_federation_id,
            };
            dbtx.insert_entry(&new_federation_key, &new_federation_config)
                .await;
        }
    }
    Ok(())
}

async fn migrate_to_v3(mut ctx: GeneralDbMigrationFnContext<'_>) -> Result<(), anyhow::Error> {
    let mut dbtx = ctx.dbtx();

    // If there is no old gateway configuration, there is nothing to do.
    if let Some(old_gateway_config) = dbtx.remove_entry(&GatewayConfigurationKeyV1).await {
        let new_gateway_config = GatewayConfigurationV2 {
            num_route_hints: old_gateway_config.num_route_hints,
            routing_fees: old_gateway_config.routing_fees,
            network: old_gateway_config.network,
        };
        dbtx.insert_entry(&GatewayConfigurationKeyV2, &new_gateway_config)
            .await;
    }

    Ok(())
}

async fn migrate_to_v4(mut ctx: GeneralDbMigrationFnContext<'_>) -> Result<(), anyhow::Error> {
    let mut dbtx = ctx.dbtx();

    dbtx.remove_entry(&GatewayConfigurationKeyV2).await;

    let configs = dbtx
        .find_by_prefix(&FederationConfigKeyPrefixV1)
        .await
        .collect::<Vec<_>>()
        .await;
    for (fed_id, _old_config) in configs {
        if let Some(old_federation_config) = dbtx.remove_entry(&fed_id).await {
            let new_fed_config = FederationConfig {
                invite_code: old_federation_config.invite_code,
                federation_index: old_federation_config.federation_index,
                lightning_fee: old_federation_config.fees.into(),
                transaction_fee: PaymentFee::TRANSACTION_FEE_DEFAULT,
                connector: Connector::default(),
            };
            let new_key = FederationConfigKey { id: fed_id.id };
            dbtx.insert_new_entry(&new_key, &new_fed_config).await;
        }
    }
    Ok(())
}

/// Introduced in v0.5, there is a db key clash between the `FederationConfig`
/// record and the isolated databases used for each client. We must migrate the
/// isolated databases to be behind the `ClientDatabase` prefix to allow the
/// gateway to properly read the federation configs.
async fn migrate_to_v5(mut ctx: GeneralDbMigrationFnContext<'_>) -> Result<(), anyhow::Error> {
    let mut dbtx = ctx.dbtx();
    migrate_federation_configs(&mut dbtx).await
}

async fn migrate_federation_configs(
    dbtx: &mut DatabaseTransaction<'_>,
) -> Result<(), anyhow::Error> {
    // We need to migrate all isolated database entries to be behind the 0x10
    // prefix. The problem is, if there is a `FederationId` that starts with
    // 0x04, we cannot read the `FederationId` because the database will be confused
    // between the isolated DB and the `FederationConfigKey` record. To solve this,
    // we try and decode each key as a Federation ID and each value as a
    // FederationConfig. If that is successful and the federation ID in the
    // config matches the key, then we skip that record and migrate the rest of
    // the entries.
    let problem_entries = dbtx
        .raw_find_by_prefix(&[0x04])
        .await?
        .collect::<BTreeMap<_, _>>()
        .await;
    for (mut problem_key, value) in problem_entries {
        // Try and decode the key as a FederationId and the value as a FederationConfig
        // The key should be 33 bytes because a FederationID is 32 bytes and there is a
        // 1 byte prefix.
        if problem_key.len() == 33 {
            if let Ok(federation_id) = FederationId::consensus_decode_whole(
                &problem_key[1..33],
                &ModuleDecoderRegistry::default(),
            ) {
                if let Ok(federation_config) = FederationConfig::consensus_decode_whole(
                    &value,
                    &ModuleDecoderRegistry::default(),
                ) {
                    if federation_id == federation_config.invite_code.federation_id() {
                        continue;
                    }
                }
            }
        }

        dbtx.raw_remove_entry(&problem_key).await?;
        let mut new_key = vec![DbKeyPrefix::ClientDatabase as u8];
        new_key.append(&mut problem_key);
        dbtx.raw_insert_bytes(&new_key, &value).await?;
    }

    // Migrate all entries of the isolated databases that don't overlap with
    // `FederationConfig` entries.
    let fed_ids = dbtx
        .find_by_prefix(&FederationConfigKeyPrefix)
        .await
        .collect::<BTreeMap<_, _>>()
        .await;
    for fed_id in fed_ids.keys() {
        let federation_id_bytes = fed_id.id.consensus_encode_to_vec();
        let isolated_entries = dbtx
            .raw_find_by_prefix(&federation_id_bytes)
            .await?
            .collect::<BTreeMap<_, _>>()
            .await;
        for (mut key, value) in isolated_entries {
            dbtx.raw_remove_entry(&key).await?;
            let mut new_key = vec![DbKeyPrefix::ClientDatabase as u8];
            new_key.append(&mut key);
            dbtx.raw_insert_bytes(&new_key, &value).await?;
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
mod migration_tests;
