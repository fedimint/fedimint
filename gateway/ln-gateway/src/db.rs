use std::collections::BTreeMap;

use bitcoin::Network;
use bitcoin_hashes::sha256;
use fedimint_core::api::InviteCode;
use fedimint_core::config::FederationId;
use fedimint_core::db::{DatabaseVersion, ServerMigrationFn};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_common::serde_routing_fees;
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

pub const GATEWAYD_DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    FederationConfig = 0x04,
    GatewayPublicKey = 0x06,
    GatewayConfiguration = 0x07,
    PreimageAuthentication = 0x08,
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
pub struct GatewayConfigurationKey;

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct GatewayConfiguration {
    pub password: String,
    pub num_route_hints: u32,
    #[serde(with = "serde_routing_fees")]
    pub routing_fees: RoutingFees,
    pub network: Network,
}

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

pub fn get_gatewayd_database_migrations() -> BTreeMap<DatabaseVersion, ServerMigrationFn> {
    BTreeMap::new()
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::str::FromStr;

    use anyhow::ensure;
    use bitcoin::Network;
    use bitcoin_hashes::{sha256, Hash};
    use fedimint_core::api::InviteCode;
    use fedimint_core::config::FederationId;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
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
        FederationConfig, FederationIdKey, GatewayConfiguration, GatewayConfigurationKey,
        GatewayPublicKey, PreimageAuthentication,
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

        let gateway_configuration = GatewayConfiguration {
            password: "EXAMPLE".to_string(),
            num_route_hints: 2,
            routing_fees: DEFAULT_FEES,
            network: Network::Regtest,
        };

        dbtx.insert_new_entry(&GatewayConfigurationKey, &gateway_configuration)
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
                Box::pin(async move {
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
                let mut dbtx = db.begin_transaction().await;

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
