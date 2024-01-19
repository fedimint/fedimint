use std::str::FromStr;

use assert_matches::assert_matches;
use fedimint_client::Client;
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_ln_client::{
    InternalPayState, LightningClientInit, LightningClientModule, LightningOperationMeta,
    LnPayState, LnReceiveState, OutgoingLightningPayment, PayType,
};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_common::ln_operation;
use fedimint_ln_server::LightningInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::{GatewayTest, DEFAULT_GATEWAY_PASSWORD};
use lightning_invoice::Bolt11Invoice;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_server());
    fixtures.with_module(LightningClientInit, LightningInit, ln_params)
}

/// Setup a gateway connected to the fed and client
async fn gateway(fixtures: &Fixtures, fed: &FederationTest) -> GatewayTest {
    let lnd = fixtures.lnd().await;
    let mut gateway = fixtures
        .new_gateway(lnd, 0, Some(DEFAULT_GATEWAY_PASSWORD.to_string()))
        .await;
    gateway.connect_fed(fed).await;
    gateway
}

async fn pay_invoice(
    client: &Client,
    invoice: Bolt11Invoice,
) -> anyhow::Result<OutgoingLightningPayment> {
    let ln_module = client.get_first_module::<LightningClientModule>();
    let gateway = ln_module.select_active_gateway_opt().await;
    ln_module.pay_bolt11_invoice(gateway, invoice, ()).await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_switch_active_gateway() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let mut gateway1 = fixtures
        .new_gateway(
            fixtures.lnd().await,
            0,
            Some(DEFAULT_GATEWAY_PASSWORD.to_string()),
        )
        .await;
    let mut gateway2 = fixtures
        .new_gateway(
            fixtures.cln().await,
            0,
            Some(DEFAULT_GATEWAY_PASSWORD.to_string()),
        )
        .await;

    // Client selects a gateway by default
    gateway1.connect_fed(&fed).await;
    let key1 = gateway1.get_gateway_id();
    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()
            .select_active_gateway()
            .await?
            .gateway_id,
        key1
    );

    gateway2.connect_fed(&fed).await;
    let key2 = gateway1.get_gateway_id();
    let gateways = client
        .get_first_module::<LightningClientModule>()
        .fetch_registered_gateways()
        .await
        .unwrap();
    assert_eq!(gateways.len(), 2);

    client
        .get_first_module::<LightningClientModule>()
        .set_active_gateway(&key2)
        .await?;
    assert_eq!(
        client
            .get_first_module::<LightningClientModule>()
            .select_active_gateway()
            .await?
            .gateway_id,
        key2
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_can_attach_extra_meta_to_receive_operation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    let extra_meta = "internal payment with no gateway registered".to_string();
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()
        .create_bolt11_invoice(
            sats(250),
            "with-markers".to_string(),
            None,
            extra_meta.clone(),
        )
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    // Pay the invoice from client2
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Verify that we can retrieve the extra metadata that was attached
    let operation = ln_operation(&client1, op).await?;
    let op_meta = operation
        .meta::<LightningOperationMeta>()
        .extra_meta
        .to_string();
    assert_eq!(serde_json::to_string(&extra_meta)?, op_meta);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_pay_same_internal_invoice_twice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    // TEST internal payment when there are no gateways registered
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()
        .create_bolt11_invoice(sats(250), "with-markers".to_string(), None, ())
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice.clone()).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
            assert_eq!(sub1.ok().await?, LnReceiveState::AwaitingFunds);
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    // Pay the invoice again and verify that it does not deduct the balance, but it
    // does return the preimage
    let prev_balance = client2.get_balance().await;
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
        }
        _ => panic!("Expected internal payment!"),
    }

    let same_balance = client2.get_balance().await;
    assert_eq!(prev_balance, same_balance);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_protects_preimage_for_payment() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let gw = gateway(&fixtures, &fed).await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client1
    let (op, outpoint) = client1_dummy_module.print_money(sats(10000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(10000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    let cln = fixtures.cln().await;
    let invoice = cln.invoice(Amount::from_sats(100), None).await?;

    // Pay invoice with client1
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client1, invoice.clone()).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client1
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    // Verify that client2 cannot pay the same invoice and the preimage is not
    // returned
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice.clone()).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::WaitingForRefund { .. });
            assert_matches!(sub.ok().await?, LnPayState::Refunded { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    drop(gw);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_pay_same_external_invoice_twice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let gw = gateway(&fixtures, &fed).await;
    let dummy_module = client.get_first_module::<DummyClientModule>();

    // Print money for client
    let (op, outpoint) = dummy_module.print_money(sats(1000)).await?;
    client.await_primary_module_output(op, outpoint).await?;

    let cln = fixtures.cln().await;
    let invoice = cln.invoice(Amount::from_sats(100), None).await?;

    // Pay the invoice for the first time
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client, invoice.clone()).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    let prev_balance = client.get_balance().await;

    // Pay the invoice again and verify that it does not deduct the balance, but it
    // does return the preimage
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client, invoice).await?;
    match payment_type {
        PayType::Lightning(operation_id) => {
            let mut sub = client
                .get_first_module::<LightningClientModule>()
                .subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            assert_eq!(sub.ok().await?, LnPayState::Created);
            assert_eq!(sub.ok().await?, LnPayState::Funded);
            assert_matches!(sub.ok().await?, LnPayState::Success { .. });
        }
        _ => panic!("Expected lightning payment!"),
    }

    let same_balance = client.get_balance().await;
    assert_eq!(prev_balance, same_balance);

    drop(gw);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn makes_internal_payments_within_federation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>();

    // Print money for client2
    let (op, outpoint) = client2_dummy_module.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    // TEST internal payment when there are no gateways registered
    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()
        .create_bolt11_invoice(sats(250), "with-markers".to_string(), None, ())
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
            assert_eq!(sub1.ok().await?, LnReceiveState::AwaitingFunds);
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    // TEST internal payment when there is a registered gateway
    gateway(&fixtures, &fed).await;

    let (op, invoice, _) = client1
        .get_first_module::<LightningClientModule>()
        .create_bolt11_invoice(sats(250), "with-gateway-hint".to_string(), None, ())
        .await?;
    let mut sub1 = client1
        .get_first_module::<LightningClientModule>()
        .subscribe_ln_receive(op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = pay_invoice(&client2, invoice).await?;
    match payment_type {
        PayType::Internal(op_id) => {
            let mut sub2 = client2
                .get_first_module::<LightningClientModule>()
                .subscribe_internal_pay(op_id)
                .await?
                .into_stream();
            assert_eq!(sub2.ok().await?, InternalPayState::Funding);
            assert_matches!(sub2.ok().await?, InternalPayState::Preimage { .. });
            assert_eq!(sub1.ok().await?, LnReceiveState::Funded);
            assert_eq!(sub1.ok().await?, LnReceiveState::AwaitingFunds);
            assert_eq!(sub1.ok().await?, LnReceiveState::Claimed);
        }
        _ => panic!("Expected internal payment!"),
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_wrong_network_invoice() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client1 = fed.new_client().await;
    gateway(&fixtures, &fed).await;

    // Signet invoice should fail on regtest
    let signet_invoice = Bolt11Invoice::from_str(
        "lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",
    )
    .unwrap();

    let error = pay_invoice(&client1, signet_invoice).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "Invalid invoice currency: expected=Regtest, got=Signet"
    );

    Ok(())
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::str::FromStr;

    use anyhow::{ensure, Context};
    use bitcoin_hashes::Hash;
    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_LN;
    use fedimint_core::db::{
        apply_migrations, DatabaseTransaction, DatabaseVersion, DatabaseVersionKey,
        IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::encoding::Encodable;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::{CommonModuleInit, DynServerModuleInit};
    use fedimint_core::util::SafeUrl;
    use fedimint_core::{OutPoint, PeerId, ServerModule, TransactionId};
    use fedimint_ln_common::contracts::incoming::{
        FundedIncomingContract, IncomingContract, IncomingContractOffer, OfferId,
    };
    use fedimint_ln_common::contracts::{
        outgoing, ContractId, DecryptedPreimage, EncryptedPreimage, FundedContract,
        PreimageDecryptionShare, PreimageKey,
    };
    use fedimint_ln_common::db::{
        AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, BlockCountVoteKey,
        BlockCountVotePrefix, ContractKey, ContractKeyPrefix, ContractUpdateKey,
        ContractUpdateKeyPrefix, DbKeyPrefix, EncryptedPreimageIndexKey,
        EncryptedPreimageIndexKeyPrefix, LightningAuditItemKey, LightningAuditItemKeyPrefix,
        LightningGatewayKey, LightningGatewayKeyPrefix, OfferKey, OfferKeyPrefix,
        ProposeDecryptionShareKey, ProposeDecryptionShareKeyPrefix,
    };
    use fedimint_ln_common::{
        ContractAccount, LightningCommonInit, LightningGateway, LightningGatewayRegistration,
        LightningOutputOutcomeV0,
    };
    use fedimint_ln_server::Lightning;
    use fedimint_testing::db::{
        prepare_db_migration_snapshot, validate_migrations, BYTE_32, BYTE_33, BYTE_8, STRING_64,
    };
    use futures::StreamExt;
    use lightning_invoice::RoutingFees;
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand::rngs::OsRng;
    use strum::IntoEnumIterator;
    use threshold_crypto::G1Projective;

    use crate::LightningInit;

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_server_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        dbtx.insert_new_entry(&DatabaseVersionKey, &DatabaseVersion(0))
            .await;

        let contract_id = ContractId::from_str(STRING_64).unwrap();
        let amount = fedimint_core::Amount { msats: 1000 };
        let threshold_key = threshold_crypto::PublicKey::from(G1Projective::identity());
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let incoming_contract = IncomingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(PreimageKey(BYTE_33), &threshold_key),
            decrypted_preimage: DecryptedPreimage::Some(PreimageKey(BYTE_33)),
            gateway_key: pk,
        };
        let out_point = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };
        let incoming_contract = FundedContract::Incoming(FundedIncomingContract {
            contract: incoming_contract,
            out_point,
        });
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount,
                contract: incoming_contract.clone(),
            },
        )
        .await;
        let outgoing_contract = FundedContract::Outgoing(outgoing::OutgoingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&[0, 2, 3, 4, 5, 6, 7, 8]),
            gateway_key: pk,
            timelock: 1000000,
            user_key: pk,
            cancelled: false,
        });
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount,
                contract: outgoing_contract.clone(),
            },
        )
        .await;

        let incoming_offer = IncomingContractOffer {
            amount: fedimint_core::Amount { msats: 1000 },
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(PreimageKey(BYTE_33), &threshold_key),
            expiry_time: None,
        };
        dbtx.insert_new_entry(&OfferKey(incoming_offer.hash), &incoming_offer)
            .await;

        let contract_update_key = ContractUpdateKey(OutPoint {
            txid: TransactionId::from_slice(&BYTE_32).unwrap(),
            out_idx: 0,
        });
        let lightning_output_outcome = LightningOutputOutcomeV0::Offer {
            id: OfferId::from_str(STRING_64).unwrap(),
        };
        dbtx.insert_new_entry(&contract_update_key, &lightning_output_outcome)
            .await;

        let preimage_decryption_share = PreimageDecryptionShare(Standard.sample(&mut OsRng));
        dbtx.insert_new_entry(
            &ProposeDecryptionShareKey(contract_id),
            &preimage_decryption_share,
        )
        .await;

        dbtx.insert_new_entry(
            &AgreedDecryptionShareKey(contract_id, 0.into()),
            &preimage_decryption_share,
        )
        .await;

        let gateway = LightningGatewayRegistration {
            info: LightningGateway {
                mint_channel_id: 100,
                gateway_redeem_key: pk,
                node_pub_key: pk,
                lightning_alias: "FakeLightningAlias".to_string(),
                api: SafeUrl::parse("http://example.com")
                    .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
                route_hints: vec![],
                fees: RoutingFees {
                    base_msat: 0,
                    proportional_millionths: 0,
                },
                gateway_id: pk,
                supports_private_payments: false,
            },
            valid_until: fedimint_core::time::now(),
            vetted: false,
        };
        dbtx.insert_new_entry(&LightningGatewayKey(pk), &gateway)
            .await;

        dbtx.insert_new_entry(&BlockCountVoteKey(PeerId::from(0)), &1)
            .await;

        dbtx.insert_new_entry(&EncryptedPreimageIndexKey("foobar".consensus_hash()), &())
            .await;

        dbtx.insert_new_entry(
            &LightningAuditItemKey::from_funded_contract(&incoming_contract),
            &amount,
        )
        .await;

        dbtx.insert_new_entry(
            &LightningAuditItemKey::from_funded_contract(&outgoing_contract),
            &amount,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_server_db_migration_snapshots() -> anyhow::Result<()> {
        prepare_db_migration_snapshot(
            "lightning-server-v0",
            |dbtx| {
                Box::pin(async move {
                    create_server_db_with_v0_data(dbtx).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_LN,
                LightningCommonInit::KIND,
                <Lightning as ServerModule>::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrations() -> anyhow::Result<()> {
        validate_migrations(
            "lightning-server",
            |db| async move {
                let module = DynServerModuleInit::from(LightningInit);
                apply_migrations(
                    &db,
                    module.module_kind().to_string(),
                    module.database_version(),
                    module.get_database_migrations(),
                )
                .await
                .context("Error applying migrations to temp database")?;

                // Verify that all of the data from the lightning namespace can be read. If a
                // database migration failed or was not properly supplied,
                // the struct will fail to be read.
                let mut dbtx = db.begin_transaction().await;

                for prefix in DbKeyPrefix::iter() {
                    match prefix {
                        DbKeyPrefix::Contract => {
                            let contracts = dbtx
                                .find_by_prefix(&ContractKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_contracts = contracts.len();
                            ensure!(
                                num_contracts > 0,
                                "validate_migrations was not able to read any contracts"
                            );
                        }
                        DbKeyPrefix::AgreedDecryptionShare => {
                            let agreed_decryption_shares = dbtx
                                .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = agreed_decryption_shares.len();
                            ensure!(
                                num_shares > 0,
                                "validate_migrations was not able to read any AgreedDecryptionShares"
                            );
                        }
                        DbKeyPrefix::ContractUpdate => {
                            let contract_updates = dbtx
                                .find_by_prefix(&ContractUpdateKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_updates = contract_updates.len();
                            ensure!(
                                num_updates > 0,
                                "validate_migrations was not able to read any ContractUpdates"
                            );
                        }
                        DbKeyPrefix::LightningGateway => {
                            let gateways = dbtx
                                .find_by_prefix(&LightningGatewayKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_gateways = gateways.len();
                            ensure!(
                                num_gateways > 0,
                                "validate_migrations was not able to read any LightningGateways"
                            );
                        }
                        DbKeyPrefix::Offer => {
                            let offers = dbtx
                                .find_by_prefix(&OfferKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_offers = offers.len();
                            ensure!(
                                num_offers > 0,
                                "validate_migrations was not able to read any Offers"
                            );
                        }
                        DbKeyPrefix::ProposeDecryptionShare => {
                            let proposed_decryption_shares = dbtx
                                .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = proposed_decryption_shares.len();
                            ensure!(
                                num_shares > 0,
                                "validate_migrations was not able to read any ProposeDecryptionShares"
                            );
                        }
                        DbKeyPrefix::BlockCountVote => {
                            let block_count_vote = dbtx
                                .find_by_prefix(&BlockCountVotePrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_votes = block_count_vote.len();
                            ensure!(
                                num_votes > 0,
                                "validate_migrations was not able to read any BlockCountVote"
                            );
                        }
                        DbKeyPrefix::EncryptedPreimageIndex => {
                            let encrypted_preimage_index = dbtx
                                .find_by_prefix(&EncryptedPreimageIndexKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = encrypted_preimage_index.len();
                            ensure!(
                                num_shares > 0,
                                "validate_migrations was not able to read any EncryptedPreimageIndexKeys"
                            );
                        }
                        DbKeyPrefix::LightningAuditItem => {
                            let audit_keys = dbtx
                                .find_by_prefix(&LightningAuditItemKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;

                            let num_audit_items = audit_keys.len();
                            ensure!(
                                num_audit_items == 2,
                                "validate_migrations was not able to read both LightningAuditItemKeys"
                            );
                        }
                    }
                }
                Ok(())
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_LN,
                LightningCommonInit::KIND,
                <Lightning as ServerModule>::decoder(),
            )]),
        )
        .await
    }
}
