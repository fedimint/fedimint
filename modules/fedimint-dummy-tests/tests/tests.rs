use anyhow::bail;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_client_module::module::OutPointRange;
use fedimint_core::config::ClientModuleConfig;
use fedimint_core::core::{IntoDynInstance, ModuleKind, OperationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::{AmountUnit, Amounts, ModuleConsensusVersion};
use fedimint_core::secp256k1::Secp256k1;
use fedimint_core::{Amount, OutPoint, sats};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyClientConfig;
use fedimint_dummy_common::{
    DummyInput, DummyInputV1, DummyOutput, DummyOutputV1, KIND, broken_fed_key_pair, fed_key_pair,
};
use fedimint_dummy_server::DummyInit;
use fedimint_testing::fixtures::Fixtures;

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit)
}

#[tokio::test(flavor = "multi_thread")]
async fn can_print_and_send_money_bitcoin() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;

    let client1_dummy_module = client1.get_first_module::<DummyClientModule>()?;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;
    let (_, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1_dummy_module.receive_money_hack(outpoint).await?;
    assert_eq!(client1.get_balance_for_btc().await?, sats(1000));

    let outpoint = client1_dummy_module
        .send_money(
            client2_dummy_module.account(),
            sats(250),
            AmountUnit::BITCOIN,
        )
        .await?;
    client2_dummy_module.receive_money_hack(outpoint).await?;
    assert_eq!(client1.get_balance_for_btc().await?, sats(750));
    assert_eq!(client2.get_balance_for_btc().await?, sats(250));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn can_print_and_send_money_other_unit() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;

    let client1_dummy_module = client1.get_first_module::<DummyClientModule>()?;
    let client2_dummy_module = client2.get_first_module::<DummyClientModule>()?;

    // Use a custom AmountUnit with value 1
    let custom_unit = AmountUnit::new_custom(1);

    let (_, outpoint) = client1_dummy_module
        .print_money_units(sats(1000), custom_unit, fed_key_pair())
        .await?;
    client1_dummy_module.receive_money_hack(outpoint).await?;
    assert_eq!(
        client1_dummy_module.get_balance(custom_unit).await?,
        sats(1000)
    );

    let outpoint = client1_dummy_module
        .send_money(client2_dummy_module.account(), sats(250), custom_unit)
        .await?;
    client2_dummy_module.receive_money_hack(outpoint).await?;
    assert_eq!(
        client1_dummy_module.get_balance(custom_unit).await?,
        sats(750)
    );
    assert_eq!(
        client2_dummy_module.get_balance(custom_unit).await?,
        sats(250)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn client_ignores_unknown_module() {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;

    let mut cfg = client.config().await;
    let module_id = 2142;
    let extra_mod = ClientModuleConfig::from_typed(
        module_id,
        ModuleKind::from_static_str("unknown_module"),
        ModuleConsensusVersion::new(0, 0),
        DummyClientConfig {
            tx_fee: Amount::from_sats(1),
        },
    )
    .unwrap();
    cfg.modules.insert(2142, extra_mod);

    // Test that building the client worked
    let _client = fed
        .new_client_with(cfg, MemDatabase::new().into(), None)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn federation_should_abort_if_balance_sheet_is_negative() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;

    let (panic_sender, panic_receiver) = std::sync::mpsc::channel::<()>();
    let prev_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let panic_str = info.to_string();
        if panic_str
            .contains("Balance sheet of the fed has gone negative, this should never happen!")
        {
            // The first panic may lead to the receiver being dropped, so we have to swallow
            // the error here
            let _ = panic_sender.send(());
        }

        prev_panic_hook(info);
    }));

    let dummy = client.get_first_module::<DummyClientModule>()?;
    let op_id = OperationId(rand::random());
    let account_kp = broken_fed_key_pair();
    let input = ClientInput::<DummyInput> {
        input: DummyInputV1 {
            amount: sats(1000),
            unit: AmountUnit::BITCOIN,
            account: account_kp.public_key(),
        }
        .into(),
        amounts: Amounts::new_bitcoin_msats(1000),
        keys: vec![account_kp],
    };

    let tx = TransactionBuilder::new()
        .with_inputs(ClientInputBundle::new_no_sm(vec![input]).into_dyn(dummy.id));
    let meta_gen = |change_range: OutPointRange| OutPoint {
        txid: change_range.txid(),
        out_idx: 0,
    };
    client
        .finalize_and_submit_transaction(op_id, KIND.as_str(), meta_gen, tx)
        .await?;

    // Make sure we panicked with the right message
    panic_receiver.recv().expect("Sender not dropped");

    Ok(())
}

/// A proper transaction is balanced, which means the sum of its inputs and
/// outputs are the same.
/// In this case we create a transaction with zero inputs and one output, which
/// the federation should reject because it's unbalanced.
#[tokio::test(flavor = "multi_thread")]
async fn unbalanced_transactions_get_rejected() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;

    let dummy_module = client.get_first_module::<DummyClientModule>()?;
    let output = ClientOutput::<DummyOutput> {
        output: DummyOutputV1 {
            amount: sats(1000),
            unit: AmountUnit::BITCOIN,
            account: dummy_module.account(),
        }
        .into(),
        amounts: Amounts::new_bitcoin(sats(1000)),
    };
    let tx = TransactionBuilder::new()
        .with_outputs(ClientOutputBundle::new_no_sm(vec![output]).into_dyn(dummy_module.id));
    let (tx, _) = tx.build(&Secp256k1::new(), rand::thread_rng());

    if client
        .api()
        .submit_transaction(tx)
        .await
        .try_into_inner(client.decoders())
        .unwrap()
        .0
        .is_ok()
    {
        bail!("Should have been rejected")
    }

    Ok(())
}

mod fedimint_migration_tests {
    use anyhow::ensure;
    use fedimint_client::module_init::DynClientModuleInit;
    use fedimint_core::core::OperationId;
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::encoding::Encodable;
    use fedimint_core::module::AmountUnit;
    use fedimint_core::{Amount, BitcoinHash, OutPoint, TransactionId, secp256k1};
    use fedimint_dummy_client::db::{
        DummyClientFundsKeyV0, DummyClientFundsKeyV1, DummyClientNameKey,
    };
    use fedimint_dummy_client::states::DummyStateMachine;
    use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
    use fedimint_dummy_common::{DummyCommonInit, DummyOutputOutcome};
    use fedimint_dummy_server::DummyInit;
    use fedimint_dummy_server::db::{
        DbKeyPrefix, DummyFundsKeyV0, DummyFundsPrefixV1, DummyOutcomeKey, DummyOutcomePrefix,
    };
    use fedimint_logging::TracingSetup;
    use fedimint_server::core::DynServerModuleInit;
    use fedimint_testing::db::{
        BYTE_32, TEST_MODULE_INSTANCE_ID, snapshot_db_migrations, snapshot_db_migrations_client,
        validate_migrations_client, validate_migrations_server,
    };
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use strum::IntoEnumIterator;
    use tracing::info;

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_server_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        // Write example v0 funds record to the database
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        dbtx.insert_new_entry(&DummyFundsKeyV0(pk), &()).await;

        // Write example v0 outcome record to the database
        let txid = TransactionId::from_slice(&BYTE_32).unwrap();
        dbtx.insert_new_entry(
            &DummyOutcomeKey(OutPoint { txid, out_idx: 0 }),
            &DummyOutputOutcome(Amount::from_sats(1000), AmountUnit::BITCOIN, pk),
        )
        .await;

        dbtx.commit_tx().await;
    }

    async fn create_client_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Write example v0 `ClientFunds`
        dbtx.insert_new_entry(&DummyClientFundsKeyV0, &()).await;

        dbtx.commit_tx().await;
    }

    fn create_client_states() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        // Create an active state and inactive state that will not be migrated.
        let input_state: Vec<u8> = {
            let mut bytes = Vec::new();
            bytes.append(&mut Amount::from_sats(1000).consensus_encode_to_vec());
            bytes.append(
                &mut TransactionId::from_slice(&BYTE_32)
                    .expect("Couldn't create TransactionId")
                    .consensus_encode_to_vec(),
            );
            bytes.append(&mut OperationId::new_random().consensus_encode_to_vec());
            bytes
        };

        let input_variant: Vec<u8> = {
            let mut bytes = Vec::new();
            bytes.append(&mut TEST_MODULE_INSTANCE_ID.consensus_encode_to_vec());
            bytes.append(&mut 0u64.consensus_encode_to_vec()); // Input variant.
            bytes.append(&mut input_state.consensus_encode_to_vec());
            bytes
        };

        // Create and active state and inactive state that will be migrated.
        let unreachable_operation_id = OperationId::new_random();
        let unreachable_state: Vec<u8> = {
            let mut bytes = Vec::new();
            bytes.append(&mut unreachable_operation_id.consensus_encode_to_vec());
            bytes.append(&mut TransactionId::all_zeros().consensus_encode_to_vec());
            bytes.append(&mut Amount::from_sats(1000).consensus_encode_to_vec());
            bytes
        };

        let unreachable_variant: Vec<u8> = {
            let mut bytes = Vec::new();
            bytes.append(&mut TEST_MODULE_INSTANCE_ID.consensus_encode_to_vec());
            bytes.append(&mut 5u64.consensus_encode_to_vec()); // Unreachable variant
            bytes.append(&mut unreachable_state.consensus_encode_to_vec());
            bytes
        };

        (
            vec![input_variant.clone(), unreachable_variant.clone()],
            vec![input_variant, unreachable_variant],
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, DummyCommonInit>("dummy-server-v0", |db| {
            Box::pin(async {
                create_server_db_with_v0_data(db).await;
            })
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        let module = DynServerModuleInit::from(DummyInit);
        validate_migrations_server(module, "dummy-server", |db| async move {
            let mut dbtx = db.begin_transaction_nc().await;
            for prefix in DbKeyPrefix::iter() {
                match prefix {
                    DbKeyPrefix::Funds => {
                        let funds = dbtx
                            .find_by_prefix(&DummyFundsPrefixV1)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_funds = funds.len();
                        ensure!(
                            num_funds > 0,
                            "validate_migrations was not able to read any funds for version 0"
                        );
                        info!("Validated Funds");
                    }
                    DbKeyPrefix::Outcome => {
                        let outcomes = dbtx
                            .find_by_prefix(&DummyOutcomePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_outcomes = outcomes.len();
                        ensure!(
                            num_outcomes > 0,
                            "validate_migration was not able to read any outcomes for version 0"
                        );
                        info!("Validated Outcome");
                    }
                }
            }

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, DummyCommonInit>(
            "dummy-client-v0",
            |db| Box::pin(async { create_client_db_with_v0_data(db).await }),
            create_client_states,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        let module = DynClientModuleInit::from(DummyClientInit);

        validate_migrations_client::<_, _, DummyClientModule>(module, "dummy-client", |db, active_states, inactive_states| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            // After applying migrations, validate that `ClientName` cannot currently be
            // read
            ensure!(
                dbtx.get_value(&DummyClientNameKey).await.is_none(),
                "DatabaseVersion was not migrated successfully, since ClientName is not none"
            );

            for prefix in fedimint_dummy_client::db::DbKeyPrefix::iter() {
                match prefix {
                    fedimint_dummy_client::db::DbKeyPrefix::ClientFunds => {
                        let funds = dbtx.get_value(&DummyClientFundsKeyV1).await;
                        ensure!(
                            funds.is_some(),
                            "validate_migrations was not able to read any client funds"
                        );
                        info!("Validated client funds");
                    }
                    fedimint_dummy_client::db::DbKeyPrefix::ClientName => {
                        // No need to validate re-reading of ClientName, it
                        // is only used to validate that the
                        // `DatabaseVersion` key
                        // was migrated successfully.
                    }
                    fedimint_dummy_client::db::DbKeyPrefix::ExternalReservedStart
                    | fedimint_dummy_client::db::DbKeyPrefix::CoreInternalReservedStart
                    | fedimint_dummy_client::db::DbKeyPrefix::CoreInternalReservedEnd => {}
                }
            }

            // Verify that after the state machine migrations, there is one `Input` state and no `Unreachable` states.
            let mut input_count = 0;
            for active_state in active_states {
                match active_state {
                    DummyStateMachine::Input(_, _, _, _)  => {
                        input_count += 1;
                    }
                    DummyStateMachine::Unreachable(_, _) => panic!("State machine migration failed, active states still contain Unreachable state"),
                    _ => {}
                }
            }

            ensure!(input_count == 1, "Expecting one `Input` active state, found {input_count}");

            let mut input_count = 0;
            for inactive_state in inactive_states {
                match inactive_state {
                    DummyStateMachine::Input(_, _, _, _) => {
                        input_count += 1;
                    }
                    DummyStateMachine::Unreachable(_, _) => panic!("State machine migration failed, active states still contain Unreachable state"),
                    _ => {}
                }
            }

            ensure!(input_count == 1, "Expecting one `Input` inactive state, found {input_count}");

            Ok(())
        })
        .await
    }
}
