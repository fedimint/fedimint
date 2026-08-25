use std::str::FromStr;

use anyhow::ensure;
use bitcoin::hashes::Hash;
use fedimint_core::PeerId;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{ConnectorType, RegisteredProtocol};
use fedimint_lnv2_common::gateway_api::PaymentFee;
use fedimint_logging::TracingSetup;
use fedimint_testing::db::{
    BYTE_32, snapshot_db_migrations_with_decoders, validate_migrations_global,
};
use strum::IntoEnumIterator;
use tracing::info;

use super::{
    Amount, BTreeMap, DbKeyPrefix, Encodable, FederationConfig, FederationConfigKey,
    FederationConfigKeyPrefix, FederationConfigKeyV0, FederationConfigV0, FederationId,
    GatewayConfigurationKeyV0, GatewayConfigurationV0, GatewayDbExt, GatewayDbtxNcExt,
    GatewayPublicKey, IDatabaseTransactionOpsCoreTyped, IncomingContract, InviteCode, Keypair,
    NetworkLegacyEncodingWrapper, OsRng, PaymentImage, PreimageAuthentication,
    PreimageAuthenticationPrefix, RegisteredIncomingContractKeyV0, RegisteredIncomingContractV0,
    StreamExt, duration_since_epoch, get_gatewayd_database_migrations, migrate_federation_configs,
    migrate_registered_incoming_contracts, secp256k1, sha256,
};
use crate::GatewayPublicKeyV0;

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
        fees: PaymentFee::TRANSACTION_FEE_DEFAULT
            .try_into()
            .expect("The default transaction fee fits into RoutingFees"),
    };

    dbtx.insert_new_entry(
        &FederationConfigKeyV0 { id: federation_id },
        &federation_config,
    )
    .await;

    let context = secp256k1::Secp256k1::new();
    let (secret, _) = context.generate_keypair(&mut OsRng);
    let key_pair = secp256k1::Keypair::from_secret_key(&context, &secret);
    dbtx.insert_new_entry(&GatewayPublicKeyV0, &key_pair).await;

    let gateway_configuration = GatewayConfigurationV0 {
        password: "EXAMPLE".to_string(),
        num_route_hints: 2,
        routing_fees: PaymentFee::TRANSACTION_FEE_DEFAULT
            .try_into()
            .expect("The default transaction fee fits into RoutingFees"),
        network: NetworkLegacyEncodingWrapper(bitcoin::Network::Regtest),
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
                            .find_by_prefix(&FederationConfigKeyPrefix)
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
                        let gateway_id = dbtx
                            .get_value(&GatewayPublicKey {
                                protocol: RegisteredProtocol::Http,
                            })
                            .await;
                        ensure!(
                            gateway_id.is_some(),
                            "validate_migrations was not able to read GatewayPublicKey"
                        );
                        info!("Validated GatewayPublicKey");
                    }
                    DbKeyPrefix::PreimageAuthentication => {
                        let preimage_authentications = dbtx
                            .find_by_prefix(&PreimageAuthenticationPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_auths = preimage_authentications.len();
                        ensure!(
                            num_auths > 0,
                            "validate_migrations was not able to read any PreimageAuthentication"
                        );
                        info!("Validated PreimageAuthentication");
                    }
                    _ => {}
                }
            }
            Ok(())
        },
        (),
        "gatewayd",
        get_gatewayd_database_migrations(),
        ModuleDecoderRegistry::from_iter([]),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_registered_incoming_contract_migration() -> anyhow::Result<()> {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

    let contract = IncomingContract::new(
        tpe::AggregatePublicKey(tpe::G1Affine::generator()),
        [42; 32],
        [0; 32],
        PaymentImage::Hash([0_u8; 32].consensus_hash()),
        Amount::from_sats(1000),
        u64::MAX,
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
        Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()).public_key(),
    );

    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(
        &RegisteredIncomingContractKeyV0(contract.commitment.payment_image.clone()),
        &RegisteredIncomingContractV0 {
            federation_id: FederationId::dummy(),
            incoming_amount_msats: 1_000_000,
            contract: contract.clone(),
        },
    )
    .await;
    dbtx.commit_tx().await;

    let mut migration_dbtx = db.begin_transaction().await;
    migrate_registered_incoming_contracts(&mut migration_dbtx.to_ref_nc()).await?;
    migration_dbtx.commit_tx().await;

    let mut dbtx = db.begin_transaction().await;

    let migrated = dbtx
        .load_registered_incoming_contract(contract.commitment.payment_image.clone())
        .await
        .expect("Contract should still be registered after the migration");

    assert_eq!(migrated.federation_id, FederationId::dummy());
    assert_eq!(migrated.incoming_amount_msats, 1_000_000);
    assert_eq!(migrated.contract, contract);
    assert!(migrated.invoice_expires_at_secs > duration_since_epoch().as_secs());

    // The backfilled expiry lies in the future, so pruning up to the current
    // time must not delete the record.
    assert_eq!(
        dbtx.prune_registered_incoming_contracts(duration_since_epoch().as_secs())
            .await,
        0
    );

    // Once the cutoff passes the backfilled expiry, the record is pruned.
    assert_eq!(
        dbtx.prune_registered_incoming_contracts(migrated.invoice_expires_at_secs + 1)
            .await,
        1
    );

    assert!(
        dbtx.load_registered_incoming_contract(contract.commitment.payment_image)
            .await
            .is_none()
    );

    dbtx.commit_tx().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_isolated_db_migration() -> anyhow::Result<()> {
    async fn create_isolated_record(prefix: Vec<u8>, db: &Database) {
        // Create an isolated database the old way where there was no prefix
        let isolated_db = db.with_prefix(prefix);
        let mut isolated_dbtx = isolated_db.begin_transaction().await;

        // Insert a record into the isolated db (doesn't matter what it is)
        isolated_dbtx
            .insert_new_entry(
                &GatewayPublicKey {
                    protocol: RegisteredProtocol::Http,
                },
                &Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng()),
            )
            .await;
        isolated_dbtx.commit_tx().await;
    }

    let nonconflicting_fed_id =
        FederationId::from_str("1106afdc71a052d2787eab7e84c95803636d2a84c272eb81b4e01b27acb86c6f")
            .expect("invalid federation ID");
    let conflicting_fed_id =
        FederationId::from_str("0406afdc71a052d2787eab7e84c95803636d2a84c272eb81b4e01b27acb86c6f")
            .expect("invalid federation ID");
    let _ = TracingSetup::default().init();
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(
        &FederationConfigKey {
            id: conflicting_fed_id,
        },
        &FederationConfig {
            invite_code: InviteCode::new(
                SafeUrl::from_str("http://testfed.com").unwrap(),
                PeerId::from(0),
                conflicting_fed_id,
                None,
            ),
            federation_index: 0,
            lightning_fee: PaymentFee::TRANSACTION_FEE_DEFAULT,
            transaction_fee: PaymentFee::TRANSACTION_FEE_DEFAULT,
            // Note: deprecated, unused
            _connector: ConnectorType::Tcp,
        },
    )
    .await;

    dbtx.insert_new_entry(
        &FederationConfigKey {
            id: nonconflicting_fed_id,
        },
        &FederationConfig {
            invite_code: InviteCode::new(
                SafeUrl::from_str("http://testfed2.com").unwrap(),
                PeerId::from(0),
                nonconflicting_fed_id,
                None,
            ),
            federation_index: 1,
            lightning_fee: PaymentFee::TRANSACTION_FEE_DEFAULT,
            transaction_fee: PaymentFee::TRANSACTION_FEE_DEFAULT,
            // Note: deprecated, unused
            _connector: ConnectorType::Tcp,
        },
    )
    .await;
    dbtx.commit_tx().await;

    create_isolated_record(conflicting_fed_id.consensus_encode_to_vec(), &db).await;
    create_isolated_record(nonconflicting_fed_id.consensus_encode_to_vec(), &db).await;

    let mut migration_dbtx = db.begin_transaction().await;
    migrate_federation_configs(&mut migration_dbtx.to_ref_nc()).await?;
    migration_dbtx.commit_tx().await;

    let mut dbtx = db.begin_transaction_nc().await;

    let num_configs = dbtx
        .find_by_prefix(&FederationConfigKeyPrefix)
        .await
        .collect::<BTreeMap<_, _>>()
        .await
        .len();
    assert_eq!(num_configs, 2);

    // Verify that the client databases migrated successfully.
    let isolated_db = db.get_client_database(&conflicting_fed_id);
    let mut isolated_dbtx = isolated_db.begin_transaction_nc().await;
    assert!(
        isolated_dbtx
            .get_value(&GatewayPublicKey {
                protocol: RegisteredProtocol::Http
            })
            .await
            .is_some()
    );

    let isolated_db = db.get_client_database(&nonconflicting_fed_id);
    let mut isolated_dbtx = isolated_db.begin_transaction_nc().await;
    assert!(
        isolated_dbtx
            .get_value(&GatewayPublicKey {
                protocol: RegisteredProtocol::Http
            })
            .await
            .is_some()
    );

    Ok(())
}
