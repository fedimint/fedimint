use std::collections::BTreeMap;

use bitcoin::Network;
use bitcoin_hashes::sha256;
use fedimint_core::config::FederationId;
use fedimint_core::db::{
    CoreMigrationFn, DatabaseVersion, IDatabaseTransactionOpsCoreTyped, MigrationContext,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::{impl_db_lookup, impl_db_record, secp256k1};
use fedimint_ln_common::serde_routing_fees;
use fedimint_lnv2_common::contracts::IncomingContract;
use futures::FutureExt;
use lightning_invoice::RoutingFees;
use rand::Rng;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::rpc::rpc_server::hash_password;

pub const GATEWAYD_DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
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

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FederationIdKey {
    pub id: FederationId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct FederationIdKeyPrefix;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct FederationConfig {
    pub invite_code: InviteCode,
    pub mint_channel_id: u64,
    pub timelock_delta: u64,
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
}

impl_db_record!(
    key = FederationIdKey,
    value = FederationConfig,
    db_prefix = DbKeyPrefix::FederationConfig,
);

impl_db_lookup!(key = FederationIdKey, query_prefix = FederationIdKeyPrefix);

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct GatewayPublicKey;

impl_db_record!(
    key = GatewayPublicKey,
    value = secp256k1::KeyPair,
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
pub struct PreimageAuthentication {
    pub payment_hash: sha256::Hash,
}

impl_db_record!(
    key = PreimageAuthentication,
    value = sha256::Hash,
    db_prefix = DbKeyPrefix::PreimageAuthentication
);

#[derive(Debug, Encodable, Decodable)]
pub struct PreimageAuthenticationPrefix;

impl_db_lookup!(
    key = PreimageAuthentication,
    query_prefix = PreimageAuthenticationPrefix
);

pub fn get_gatewayd_database_migrations() -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
    let mut migrations: BTreeMap<DatabaseVersion, CoreMigrationFn> = BTreeMap::new();
    migrations.insert(DatabaseVersion(0), |ctx| migrate_to_v1(ctx).boxed());
    migrations
}

async fn migrate_to_v1(mut ctx: MigrationContext<'_>) -> Result<(), anyhow::Error> {
    let mut dbtx = ctx.dbtx();

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

#[derive(Debug, Encodable, Decodable)]
pub struct RegisteredIncomingContractKey(pub [u8; 32]);

#[derive(Debug, Encodable, Decodable)]
pub struct RegisteredIncomingContract {
    pub federation_id: FederationId,
    pub incoming_amount: u64,
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
    use bitcoin::Network;
    use bitcoin_hashes::{sha256, Hash};
    use fedimint_core::config::FederationId;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::invite_code::InviteCode;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::secp256k1;
    use fedimint_core::util::SafeUrl;
    use fedimint_logging::TracingSetup;
    use fedimint_testing::db::{
        snapshot_db_migrations_with_decoders, validate_migrations_global, BYTE_32,
    };
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use strum::IntoEnumIterator;
    use tracing::info;

    use super::{
        FederationConfig, FederationIdKey, GatewayConfigurationKey, GatewayConfigurationKeyV0,
        GatewayConfigurationV0, GatewayPublicKey, PreimageAuthentication,
    };
    use crate::db::{
        get_gatewayd_database_migrations, DbKeyPrefix, FederationIdKeyPrefix,
        PreimageAuthenticationPrefix, GATEWAYD_DATABASE_VERSION,
    };
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
        let federation_config = FederationConfig {
            invite_code,
            mint_channel_id: 2,
            timelock_delta: 10,
            fees: DEFAULT_FEES,
        };

        dbtx.insert_new_entry(&FederationIdKey { id: federation_id }, &federation_config)
            .await;

        let context = secp256k1::Secp256k1::new();
        let (secret, _) = context.generate_keypair(&mut OsRng);
        let key_pair = secp256k1::KeyPair::from_secret_key(&context, &secret);
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
            GATEWAYD_DATABASE_VERSION,
            get_gatewayd_database_migrations(),
            ModuleDecoderRegistry::from_iter([]),
        )
        .await
    }
}
