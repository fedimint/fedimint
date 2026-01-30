use std::time::Duration;

use assert_matches::assert_matches;
use bls12_381::G1Affine;
use fedimint_client::ClientHandleArc;
use fedimint_client::backup::{ClientBackup, Metadata};
use fedimint_client::transaction::{ClientInput, ClientInputBundle, TransactionBuilder};
use fedimint_client_module::ClientModule;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::task::sleep_in_test;
use fedimint_core::util::NextOrPending;
use fedimint_core::{Amount, TieredMulti, sats, secp256k1};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_logging::LOG_TEST;
use fedimint_mint_client::api::MintFederationApi;
use fedimint_mint_client::client_db::{NextECashNoteIndexKey, NoteKey};
use fedimint_mint_client::{
    MintClientInit, MintClientModule, Note, OOBNotes, ReissueExternalNotesState,
    SelectNotesWithAtleastAmount, SelectNotesWithExactAmount, SpendOOBState,
    SpendableNoteUndecoded,
};
use fedimint_mint_common::{MintInput, MintInputV0, Nonce};
use fedimint_mint_server::MintInit;
use fedimint_testing::fixtures::{Fixtures, TIMEOUT};
use futures::StreamExt;
use secp256k1::Keypair;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

const EXPECTED_MAXIMUM_FEE: Amount = Amount::from_sats(20);

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);

    fixtures.with_module(DummyClientInit, DummyInit)
}

/// Create real e-cash by submitting a DummyInput transaction.
/// The dummy server accepts any public key, so this creates "free money"
/// that gets converted to e-cash as change by the mint module.
async fn issue_ecash(client: &ClientHandleArc, amount: Amount) -> anyhow::Result<()> {
    let dummy_module = client.get_first_module::<DummyClientModule>()?;

    let dummy_input = dummy_module.create_input(amount);

    let operation_id = OperationId::new_random();

    let outpoint_range = client
        .finalize_and_submit_transaction(
            operation_id,
            "Issue e-cash via dummy module",
            |_| (),
            TransactionBuilder::new().with_inputs(dummy_input),
        )
        .await?;

    client
        .await_primary_bitcoin_module_outputs(operation_id, outpoint_range.into_iter().collect())
        .await?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BackupTestMetadata {
    custom_key: String,
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_with_invalid_signature_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;

    let keypair = Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());

    let client_input = ClientInput::<MintInput> {
        input: MintInput::V0(MintInputV0 {
            amount: Amount::from_msats(1024),
            note: Note {
                nonce: Nonce(keypair.public_key()),
                signature: tbs::Signature(G1Affine::generator()),
            },
        }),
        amounts: Amounts::new_bitcoin_msats(1024),
        keys: vec![keypair],
    };

    let operation_id = OperationId::new_random();

    let txid = client
        .finalize_and_submit_transaction(
            operation_id,
            "Claiming Invalid Ecash Note",
            |_| (),
            TransactionBuilder::new().with_inputs(
                client
                    .get_first_module::<MintClientModule>()?
                    .client_ctx
                    .make_client_inputs(ClientInputBundle::new_no_sm(vec![client_input])),
            ),
        )
        .await
        .expect("Failed to finalize transaction")
        .txid();

    assert!(
        client
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(txid)
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_out_of_band() -> anyhow::Result<()> {
    // Give client1 initial balance
    let fed = fixtures().new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    issue_ecash(&client1, sats(1000)).await?;

    // Spend from client1 to client2
    let client1_mint = client1.get_first_module::<MintClientModule>()?;
    let client2_mint = client2.get_first_module::<MintClientModule>()?;
    info!("### SPEND NOTES");
    let (op, notes) = client1_mint
        .spend_notes_with_selector(&SelectNotesWithAtleastAmount, sats(750), TIMEOUT, false, ())
        .await?;
    let sub1 = &mut client1_mint.subscribe_spend_notes(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, SpendOOBState::Created);

    info!("### REISSUE");
    let op = client2_mint.reissue_external_notes(notes, ()).await?;
    let sub2 = client2_mint.subscribe_reissue_external_notes(op).await?;
    let mut sub2 = sub2.into_stream();
    info!("### SUB2: WAIT CREATED");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Created);
    info!("### SUB2: WAIT ISSUING");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Issuing);
    info!("### SUB2: WAIT DONE");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Done);
    info!("### SUB1: WAIT SUCCESS");
    assert_eq!(sub1.ok().await?, SpendOOBState::Success);
    info!("### REISSUE: DONE");

    assert!(client1.get_balance_for_btc().await? >= sats(250).saturating_sub(EXPECTED_MAXIMUM_FEE));
    assert!(client2.get_balance_for_btc().await? >= sats(750).saturating_sub(EXPECTED_MAXIMUM_FEE));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn blind_nonce_index() -> anyhow::Result<()> {
    // Give client initial balance
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    issue_ecash(&client, sats(1000)).await?;

    // Issue e-cash and check if the blind nonce is added to the index
    let client_mint = client.get_first_module::<MintClientModule>()?;

    let mut dbtx = client_mint.db.begin_transaction().await;
    let operation_id = OperationId::new_random();
    let issuance_req = client_mint
        .create_output(&mut dbtx.to_ref_nc(), operation_id, 1, Amount::from_sats(1))
        .await;
    dbtx.commit_tx().await;

    let blind_nonce = issuance_req
        .outputs()
        .first()
        .expect("There should be at least one note in here")
        .output
        .ensure_v0_ref()?
        .blind_nonce;

    assert!(
        !client_mint.api.check_blind_nonce_used(blind_nonce).await?,
        "Blind nonce should not be used yet"
    );

    let tx = TransactionBuilder::new().with_outputs(client_mint.client_ctx.make_dyn(issuance_req));

    let change_range = client_mint
        .client_ctx
        .finalize_and_submit_transaction(operation_id, "mint", |_| (), tx)
        .await?;

    client.api().await_transaction(change_range.txid()).await;

    assert!(
        client_mint.api.check_blind_nonce_used(blind_nonce).await?,
        "Blind nonce should be used now"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // TODO: flaky https://github.com/fedimint/fedimint/issues/4508
async fn sends_ecash_oob_highly_parallel() -> anyhow::Result<()> {
    // Give client1 initial balance
    let fed = fixtures().new_fed_degraded().await;
    let client1 = fed.new_client_rocksdb().await;
    let client2 = fed.new_client_rocksdb().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>()?;
    client1_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await?;

    // We currently have a limit on DB retries, if this number is increased too much
    // we might hit it
    const NUM_PAR: u64 = 10;
    // Tests are pretty slow in CI, using the default 10s timeout worked locally but
    // failed in CI
    const ECASH_TIMEOUT: Duration = Duration::from_secs(60);

    // Spend from client1 to client2 10 times in parallel
    let mut spend_tasks = vec![];
    for num_spend in 0..NUM_PAR {
        let task_client1 = client1.clone();
        spend_tasks.push(fedimint_core::runtime::spawn(
            &format!("spend_ecash_{num_spend}"),
            async move {
                info!("Starting spend {num_spend}");
                let client1_mint = task_client1.get_first_module::<MintClientModule>().unwrap();
                let (op, notes) = client1_mint
                    .spend_notes_with_selector(
                        &SelectNotesWithAtleastAmount,
                        sats(30),
                        ECASH_TIMEOUT,
                        false,
                        (),
                    )
                    .await
                    .unwrap();
                let sub1 = &mut client1_mint
                    .subscribe_spend_notes(op)
                    .await
                    .unwrap()
                    .into_stream();
                assert_eq!(sub1.ok().await.unwrap(), SpendOOBState::Created);
                notes
            },
        ));
    }

    let note_bags = futures::stream::iter(spend_tasks)
        .then(|handle| async { handle.await.expect("Spend task failed") })
        .collect::<Vec<_>>()
        .await;
    // Since we are overspending as soon as the right denominations aren't available
    // anymore we have to use the amount actually sent and not the one requested
    let total_amount_spent: Amount = note_bags.iter().map(|bag| bag.total_amount()).sum();

    assert_eq!(
        client1.get_balance_for_btc().await?,
        sats(1000).saturating_sub(total_amount_spent)
    );

    info!(%total_amount_spent, "Sent notes");

    let mut reissue_tasks = vec![];
    for (num_reissue, notes) in note_bags.into_iter().enumerate() {
        let task_client2 = client2.clone();
        reissue_tasks.push(fedimint_core::runtime::spawn(
            &format!("reissue_ecash_{num_reissue}"),
            async move {
                info!("Starting reissue {num_reissue}");
                let client2_mint = task_client2.get_first_module::<MintClientModule>().unwrap();
                let op = client2_mint
                    .reissue_external_notes(notes, ())
                    .await
                    .unwrap();
                let sub2 = client2_mint
                    .subscribe_reissue_external_notes(op)
                    .await
                    .unwrap();
                let mut sub2 = sub2.into_stream();
                assert_eq!(sub2.ok().await.unwrap(), ReissueExternalNotesState::Created);
                info!("Reissuance {num_reissue} created");
                assert_eq!(sub2.ok().await.unwrap(), ReissueExternalNotesState::Issuing);
                info!("Reissuance {num_reissue} accepted");
                assert_eq!(sub2.ok().await.unwrap(), ReissueExternalNotesState::Done);
                info!("Reissuance {num_reissue} finished");
            },
        ));
    }

    for task in reissue_tasks {
        task.await.expect("reissue task failed");
    }

    assert!(
        client2.get_balance_for_btc().await?
            >= total_amount_spent.saturating_sub(EXPECTED_MAXIMUM_FEE)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_encode_decode_roundtrip() -> anyhow::Result<()> {
    // Give client initial balance
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let client_dummy_module = client.get_first_module::<DummyClientModule>()?;
    client_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await?;

    let metadata = Metadata::from_json_serialized(BackupTestMetadata {
        custom_key: "custom_value".into(),
    });

    let backup = client.create_backup(metadata.clone()).await?;

    let backup_bin = fedimint_core::encoding::Encodable::consensus_encode_to_vec(&backup);

    let backup_decoded: ClientBackup =
        fedimint_core::encoding::Decodable::consensus_decode_whole(&backup_bin, client.decoders())
            .expect("decode");

    assert_eq!(backup, backup_decoded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_backup_can_recover_metadata() -> anyhow::Result<()> {
    // Give client initial balance
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let client_dummy_module = client.get_first_module::<DummyClientModule>()?;
    client_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await?;

    let metadata = Metadata::from_json_serialized(BackupTestMetadata {
        custom_key: "custom_value".into(),
    });

    client.backup_to_federation(metadata.clone()).await?;
    let fetched_backup = client
        .download_backup_from_federation()
        .await?
        .expect("could not download backup");
    assert_eq!(fetched_backup.metadata, metadata);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_out_of_band_cancel() -> anyhow::Result<()> {
    // Give client initial balance
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    issue_ecash(&client, sats(1000)).await?;

    // Spend from client1 to client2
    let mint_module = client.get_first_module::<MintClientModule>()?;
    let (op, _) = mint_module
        .spend_notes_with_selector(&SelectNotesWithAtleastAmount, sats(750), TIMEOUT, false, ())
        .await?;
    let sub1 = &mut mint_module.subscribe_spend_notes(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, SpendOOBState::Created);

    mint_module.try_cancel_spend_notes(op).await;
    assert_eq!(sub1.ok().await?, SpendOOBState::UserCanceledProcessing);
    assert_eq!(sub1.ok().await?, SpendOOBState::UserCanceledSuccess);

    info!("Refund tx accepted, waiting for refunded e-cash");

    // FIXME: UserCanceledSuccess should mean the money is in our wallet
    for _ in 0..120 {
        let balance = client.get_balance_for_btc().await?;
        let expected_min_balance = sats(1000).saturating_sub(EXPECTED_MAXIMUM_FEE);
        if expected_min_balance <= balance {
            return Ok(());
        }
        debug!(target: LOG_TEST, %balance, %expected_min_balance, "Wallet balance not updated yet");
        sleep_in_test("waiting for wallet balance", Duration::from_millis(500)).await;
    }

    panic!("Did not receive refund in time");
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_out_of_band_cancel_partial() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (client, client2) = fed.two_clients().await;
    info!("### PRINT NOTES");
    issue_ecash(&client, sats(1000)).await?;

    let client2_mint = client2.get_first_module::<MintClientModule>()?;

    // Spend from client1 to client2
    info!("### SPEND NOTES");
    let mint_module = client.get_first_module::<MintClientModule>()?;
    let (spend_op, notes) = mint_module
        .spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            sats(750),
            TIMEOUT * 3,
            false,
            (),
        )
        .await?;
    let sub1 = &mut mint_module
        .subscribe_spend_notes(spend_op)
        .await?
        .into_stream();
    assert_eq!(sub1.ok().await?, SpendOOBState::Created);

    let oob_notes = notes.notes().clone();
    let federation_id = notes.federation_id_prefix();
    let mut oob_notes_iter = oob_notes.into_iter_items().rev();
    let single_note = oob_notes_iter.next().unwrap();
    let oob_notes_single_note = TieredMulti::from_iter(vec![single_note]);

    let oob_notes_single_note = OOBNotes::new(federation_id, oob_notes_single_note);

    info!("### REISSUE NOTES (single note)");
    let reissue_op = client2_mint
        .reissue_external_notes(oob_notes_single_note, ())
        .await?;

    let sub2 = client2_mint
        .subscribe_reissue_external_notes(reissue_op)
        .await?;

    let mut sub2 = sub2.into_stream();
    info!("### SUB2: WAIT CREATED");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Created);
    info!("### SUB2: WAIT ISSUING");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Issuing);
    info!("### SUB2: WAIT DONE");
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Done);
    info!("### REISSUE: DONE");

    info!("### CANCEL NOTES");
    mint_module.try_cancel_spend_notes(spend_op).await;
    assert_eq!(sub1.ok().await?, SpendOOBState::UserCanceledProcessing);
    info!("### CANCEL NOTES: must fail");
    assert_eq!(sub1.ok().await?, SpendOOBState::UserCanceledFailure);

    // FIXME: UserCanceledSuccess should mean the money is in our wallet
    for _ in 0..120 {
        let balance = client.get_balance_for_btc().await?;
        let expected_min_balance = sats(1000)
            .saturating_sub(EXPECTED_MAXIMUM_FEE)
            .saturating_sub(single_note.0);
        info!(target: LOG_TEST, %balance, %expected_min_balance, "Checking balance");
        if expected_min_balance <= balance {
            return Ok(());
        }
        sleep_in_test("waiting for wallet balance", Duration::from_millis(500)).await;
    }

    panic!("Did not receive refund in time");
}

#[tokio::test(flavor = "multi_thread")]
async fn error_zero_value_oob_spend() -> anyhow::Result<()> {
    // Give client1 initial balance
    let fed = fixtures().new_fed_degraded().await;
    let (client1, _client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>()?;
    client1_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await?;

    // Spend from client1 to client2
    let err_msg = client1
        .get_first_module::<MintClientModule>()?
        .spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            Amount::ZERO,
            TIMEOUT,
            false,
            (),
        )
        .await
        .expect_err("Zero-amount spends should be forbidden")
        .to_string();
    assert!(err_msg.contains("zero-amount"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn error_zero_value_oob_receive() -> anyhow::Result<()> {
    // Give client1 initial balance
    let fed = fixtures().new_fed_degraded().await;
    let (client1, _client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>()?;
    client1_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await?;

    // Spend from client1 to client2
    let err_msg = client1
        .get_first_module::<MintClientModule>()?
        .reissue_external_notes(
            OOBNotes::new(client1.federation_id().to_prefix(), Default::default()),
            (),
        )
        .await
        .expect_err("Zero-amount receives should be forbidden")
        .to_string();
    assert!(err_msg.contains("zero-amount"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn repair_wallet() -> anyhow::Result<()> {
    // Give client initial balance
    let fed = fixtures()
        .new_fed_builder(1)
        .disable_mint_fees()
        .build()
        .await;
    let client = fed.new_client().await;
    issue_ecash(&client, sats(1000)).await?;

    let client_mint = client.get_first_module::<MintClientModule>()?;

    // Check that repair on a good wallet does nothing
    {
        let initial_balance = client_mint
            .get_balance(
                &mut client_mint.db.begin_transaction_nc().await,
                AmountUnit::BITCOIN,
            )
            .await;
        let repair_summary = client_mint
            .try_repair_wallet(100)
            .await
            .expect("Repair should succeed");

        assert!(
            repair_summary.spent_notes.is_empty(),
            "No spent notes should be found"
        );
        assert!(
            repair_summary.used_indices.is_empty(),
            "No used indices should be found"
        );

        let new_balance = client_mint
            .get_balance(
                &mut client_mint.db.begin_transaction_nc().await,
                AmountUnit::BITCOIN,
            )
            .await;
        assert_eq!(
            initial_balance, new_balance,
            "Balance should remain unchanged after repair"
        );
    }

    // Check that already spent notes are detected and repaired
    {
        let (
            NoteKey {
                amount: first_note_amount,
                ..
            },
            first_note_undecoded,
        ): (_, SpendableNoteUndecoded) = client_mint
            .db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&fedimint_mint_client::client_db::NoteKeyPrefix)
            .await
            .next()
            .await
            .expect("At least one note exists");
        let first_note = first_note_undecoded.decode().expect("Invalid Note format");
        let reissue_operation_id = client_mint
            .reissue_external_notes(
                OOBNotes::new(
                    client.federation_id().to_prefix(),
                    TieredMulti::from_iter(vec![(first_note_amount, first_note)]),
                ),
                (),
            )
            .await
            .expect("Reissue should succeed");

        let reissue_outcome = client_mint
            .subscribe_reissue_external_notes(reissue_operation_id)
            .await?
            .await_outcome()
            .await;
        assert_eq!(
            reissue_outcome,
            Some(ReissueExternalNotesState::Done),
            "Reissue should finish"
        );

        let initial_balance = client_mint
            .get_balance(
                &mut client_mint.db.begin_transaction_nc().await,
                AmountUnit::BITCOIN,
            )
            .await;

        let repair_summary = client_mint
            .try_repair_wallet(100)
            .await
            .expect("Repair should succeed");

        assert_eq!(
            repair_summary.spent_notes.count_items(),
            1,
            "One spent note should be found"
        );
        assert!(
            repair_summary.used_indices.is_empty(),
            "No used indices should be found"
        );

        let new_balance = client_mint
            .get_balance(
                &mut client_mint.db.begin_transaction_nc().await,
                AmountUnit::BITCOIN,
            )
            .await;
        assert_eq!(
            initial_balance
                .checked_sub(first_note_amount)
                .expect("Can't underflow"),
            new_balance,
            "Balance should go down after repair"
        );
    }

    // Check that already used blind nonces are detected and repaired
    {
        let mut dbtx = client_mint.db.begin_transaction().await;
        const TEST_NOTE_INDEX_KEY: NextECashNoteIndexKey =
            NextECashNoteIndexKey(Amount::from_msats(1));
        let old_nonce_index = dbtx
            .get_value(&TEST_NOTE_INDEX_KEY)
            .await
            .expect("Amount tier exists");
        dbtx.insert_entry(&TEST_NOTE_INDEX_KEY, &(old_nonce_index - 1))
            .await
            .expect("Failed to insert test note index");
        dbtx.commit_tx().await;

        let initial_balance = client_mint
            .get_balance(
                &mut client_mint.db.begin_transaction_nc().await,
                AmountUnit::BITCOIN,
            )
            .await;

        let repair_summary = client_mint
            .try_repair_wallet(100)
            .await
            .expect("Repair should succeed");

        assert!(
            repair_summary.spent_notes.is_empty(),
            "No spent notes should be found"
        );
        assert_eq!(
            repair_summary.used_indices.count_items(),
            1,
            "One used index should be found"
        );

        let new_balance = client_mint
            .get_balance(
                &mut client_mint.db.begin_transaction_nc().await,
                AmountUnit::BITCOIN,
            )
            .await;
        assert_eq!(
            initial_balance, new_balance,
            "Balance should remain unchanged after repair"
        );
    }

    // Check that already used blind nonces with gaps in between are detected and
    // repaired
    {
        let mut dbtx = client_mint.db.begin_transaction().await;
        const TEST_NOTE_INDEX_KEY: NextECashNoteIndexKey =
            NextECashNoteIndexKey(Amount::from_msats(1));
        let old_nonce_index = dbtx
            .get_value(&TEST_NOTE_INDEX_KEY)
            .await
            .expect("Amount tier exists");
        dbtx.insert_entry(&TEST_NOTE_INDEX_KEY, &(old_nonce_index + 1))
            .await
            .expect("Failed to insert test note index");
        dbtx.commit_tx().await;

        let (_, reissue_note) = client_mint
            .spend_notes_with_selector(
                &SelectNotesWithExactAmount,
                Amount::from_msats(1),
                TIMEOUT,
                false,
                (),
            )
            .await?;
        let op_id = client_mint.reissue_external_notes(reissue_note, ()).await?;
        assert_matches!(
            client_mint
                .subscribe_reissue_external_notes(op_id)
                .await?
                .await_outcome()
                .await,
            Some(ReissueExternalNotesState::Done)
        );

        let mut dbtx = client_mint.db.begin_transaction().await;
        dbtx.insert_entry(&TEST_NOTE_INDEX_KEY, &(old_nonce_index - 1))
            .await
            .expect("Failed to insert test note index");
        dbtx.commit_tx().await;

        let initial_balance = client_mint
            .get_balance(
                &mut client_mint.db.begin_transaction_nc().await,
                AmountUnit::BITCOIN,
            )
            .await;

        let repair_summary = client_mint
            .try_repair_wallet(100)
            .await
            .expect("Repair should succeed");

        assert!(
            repair_summary.spent_notes.is_empty(),
            "No spent notes should be found"
        );
        assert_eq!(
            repair_summary.used_indices.get(Amount::from_msats(1)),
            3,
            "We should have skipped one index and reused another"
        );

        let new_balance = client_mint
            .get_balance(
                &mut client_mint.db.begin_transaction_nc().await,
                AmountUnit::BITCOIN,
            )
            .await;
        assert_eq!(
            initial_balance, new_balance,
            "Balance should remain unchanged after repair"
        );
    }

    Ok(())
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;

    use anyhow::ensure;
    use bls12_381::Scalar;
    use fedimint_client::module_init::DynClientModuleInit;
    use fedimint_client_module::module::init::recovery::{
        RecoveryFromHistory, RecoveryFromHistoryCommon,
    };
    use fedimint_core::core::OperationId;
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::{
        Amount, BitcoinHash, OutPoint, Tiered, TieredMulti, TransactionId, secp256k1,
    };
    use fedimint_derive_secret::{ChildId, DerivableSecret};
    use fedimint_logging::TracingSetup;
    use fedimint_mint_client::backup::recovery::{
        MintRecovery, MintRecoveryState, MintRecoveryStateV2,
    };
    use fedimint_mint_client::backup::{EcashBackup, EcashBackupV0};
    use fedimint_mint_client::client_db::{
        CancelledOOBSpendKey, CancelledOOBSpendKeyPrefix, NextECashNoteIndexKey,
        NextECashNoteIndexKeyPrefix, NoteKey, NoteKeyPrefix, RecoveryFinalizedKey,
        RecoveryStateKey,
    };
    use fedimint_mint_client::output::NoteIssuanceRequest;
    use fedimint_mint_client::{MintClientInit, MintClientModule, NoteIndex, SpendableNote};
    use fedimint_mint_common::{MintCommonInit, MintOutputOutcome, Nonce};
    use fedimint_mint_server::db::{
        DbKeyPrefix, MintAuditItemKey, MintAuditItemKeyPrefix, MintOutputOutcomeKey,
        MintOutputOutcomePrefix, NonceKey, NonceKeyPrefix,
    };
    use fedimint_server::core::DynServerModuleInit;
    use fedimint_testing::db::{
        BYTE_8, BYTE_32, snapshot_db_migrations, snapshot_db_migrations_client,
        validate_migrations_client, validate_migrations_server,
    };
    use ff::Field;
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use secp256k1::Keypair;
    use strum::IntoEnumIterator;
    use tbs::{
        AggregatePublicKey, BlindingKey, Message, PublicKeyShare, SecretKeyShare, Signature,
        blind_message, sign_message,
    };
    use threshold_crypto::{G1Affine, G2Affine};
    use tracing::info;

    use crate::MintInit;

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

        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let nonce_key = NonceKey(Nonce(pk));
        dbtx.insert_new_entry(&nonce_key, &()).await;

        let out_point = OutPoint {
            txid: TransactionId::from_slice(&BYTE_32).unwrap(),
            out_idx: 0,
        };

        let blinding_key = BlindingKey::random();
        let message = Message::from_bytes(&BYTE_8);
        let blinded_message = blind_message(message, blinding_key);
        let secret_key_share = SecretKeyShare(Scalar::random(&mut OsRng));
        let blind_signature_share = sign_message(blinded_message, secret_key_share);
        dbtx.insert_new_entry(
            &MintOutputOutcomeKey(out_point),
            &MintOutputOutcome::new_v0(blind_signature_share),
        )
        .await;

        let mint_audit_issuance = MintAuditItemKey::Issuance(out_point);
        let mint_audit_issuance_total = MintAuditItemKey::IssuanceTotal;
        let mint_audit_redemption = MintAuditItemKey::Redemption(nonce_key);
        let mint_audit_redemption_total = MintAuditItemKey::RedemptionTotal;

        dbtx.insert_new_entry(&mint_audit_issuance, &Amount::from_sats(1000))
            .await;
        dbtx.insert_new_entry(&mint_audit_issuance_total, &Amount::from_sats(5000))
            .await;
        dbtx.insert_new_entry(&mint_audit_redemption, &Amount::from_sats(10000))
            .await;
        dbtx.insert_new_entry(&mint_audit_redemption_total, &Amount::from_sats(15000))
            .await;

        dbtx.commit_tx().await;
    }

    async fn create_client_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        let (_, pubkey) = secp256k1::generate_keypair(&mut OsRng);
        let keypair = Keypair::new_global(&mut OsRng);

        let sig = Signature(G1Affine::generator());

        let spendable_note = SpendableNote {
            signature: sig,
            spend_key: keypair,
        };

        dbtx.insert_new_entry(
            &NoteKey {
                amount: Amount::from_sats(1000),
                nonce: Nonce(pubkey),
            },
            &spendable_note.to_undecoded(),
        )
        .await;

        dbtx.insert_new_entry(&NextECashNoteIndexKey(Amount::from_sats(1000)), &3)
            .await;

        dbtx.insert_new_entry(&CancelledOOBSpendKey(OperationId(BYTE_32)), &())
            .await;

        let mut spendable_notes = BTreeMap::new();
        spendable_notes.insert(Nonce(pubkey), (Amount::from_sats(1000), spendable_note));

        let key_share = PublicKeyShare(G2Affine::generator());
        let agg_pub_key = AggregatePublicKey(G2Affine::generator());
        let secret = DerivableSecret::new_root(&BYTE_8, &BYTE_8)
            .child_key(ChildId(0))
            .child_key(ChildId(1));
        let mut pub_key_shares = BTreeMap::new();
        let mut keys = Tiered::default();
        keys.insert(Amount::from_sats(1000), key_share);
        pub_key_shares.insert(1.into(), keys);

        let mut tbs_pks = Tiered::default();
        tbs_pks.insert(Amount::from_sats(1000), agg_pub_key);

        let backup = create_ecash_backup_v0(spendable_note, secret.clone());

        let mint_recovery_state = MintRecoveryState::V2(MintRecoveryStateV2::from_backup(
            backup,
            10,
            tbs_pks,
            pub_key_shares,
            &secret,
        ));

        MintRecovery::store_finalized(&mut dbtx.to_ref_nc(), true).await;
        dbtx.insert_new_entry(
            &RecoveryStateKey,
            &(mint_recovery_state, RecoveryFromHistoryCommon::new(0, 0, 0)),
        )
        .await;

        dbtx.commit_tx().await;
    }

    fn create_ecash_backup_v0(note: SpendableNote, secret: DerivableSecret) -> EcashBackupV0 {
        let mut map = BTreeMap::new();
        map.insert(Amount::from_sats(100), vec![note]);
        let spendable_notes = TieredMulti::new(map);
        let pending_note = (
            OutPoint {
                txid: TransactionId::from_slice(&BYTE_32).expect("TransactionId from slice failed"),
                out_idx: 0,
            },
            Amount::from_sats(10000),
            NoteIssuanceRequest::new(secp256k1::SECP256K1, &secret).0,
        );
        let pending_notes = vec![pending_note];
        let session_count = 0;
        let mut next_note_idx = Tiered::default();
        next_note_idx.insert(Amount::from_sats(1000), NoteIndex::from_u64(3));

        let backup =
            EcashBackup::new_v0(spendable_notes, pending_notes, session_count, next_note_idx);

        match backup {
            EcashBackup::V0(v0) => v0,
            _ => panic!("Expected V0 ecash backup"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, MintCommonInit>("mint-server-v0", |db| {
            Box::pin(async {
                create_server_db_with_v0_data(db).await;
            })
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        let module = DynServerModuleInit::from(MintInit);
        validate_migrations_server(module, "mint-server", |db| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            for prefix in DbKeyPrefix::iter() {
                match prefix {
                    DbKeyPrefix::NoteNonce => {
                        let nonces = dbtx
                            .find_by_prefix(&NonceKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_nonces = nonces.len();
                        ensure!(
                            num_nonces > 0,
                            "validate_migrations was not able to read any NoteNonces"
                        );
                        info!("Validated NoteNonce");
                    }
                    DbKeyPrefix::OutputOutcome => {
                        let outcomes = dbtx
                            .find_by_prefix(&MintOutputOutcomePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_outcomes = outcomes.len();
                        ensure!(
                            num_outcomes > 0,
                            "validate_migrations was not able to read any OutputOutcomes"
                        );
                        info!("Validated OutputOutcome");
                    }
                    DbKeyPrefix::MintAuditItem => {
                        let audit_items = dbtx
                            .find_by_prefix(&MintAuditItemKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_items = audit_items.len();
                        ensure!(
                            num_items > 0,
                            "validate_migrations was not able to read any MintAuditItems"
                        );
                        info!("Validated MintAuditItem");
                    }
                    DbKeyPrefix::BlindNonce => {
                        // Would require an entire re-design of the way we test
                        // here, manually testing instead for now
                    }
                    DbKeyPrefix::RecoveryItem => {
                        // New prefix for slice-based recovery, no migration
                        // needed
                    }
                    DbKeyPrefix::RecoveryBlindNonceOutpoint => {
                        // New prefix for slice-based recovery, no migration
                        // needed
                    }
                }
            }

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, MintCommonInit>(
            "mint-client-v0",
            |dbtx| Box::pin(async { create_client_db_with_v0_data(dbtx).await }),
            || (Vec::new(), Vec::new()),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        let module = DynClientModuleInit::from(MintClientInit);
        validate_migrations_client::<_, _, MintClientModule>(
            module,
            "mint-client",
            |db, _, _| async move {
                let mut dbtx = db.begin_transaction_nc().await;

                for prefix in fedimint_mint_client::client_db::DbKeyPrefix::iter() {
                    match prefix {
                        fedimint_mint_client::client_db::DbKeyPrefix::Note => {
                            let notes = dbtx
                                .find_by_prefix(&NoteKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_notes = notes.len();
                            ensure!(
                                num_notes > 0,
                                "validate_migrations was not able to read any Notes"
                            );
                            info!("Validated Notes");
                        }
                        fedimint_mint_client::client_db::DbKeyPrefix::NextECashNoteIndex => {
                            let next_index = dbtx
                                .find_by_prefix(&NextECashNoteIndexKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_next_indices = next_index.len();
                            ensure!(
                                num_next_indices > 0,
                                "validate_migrations was not able to read any NextECashNoteIndices"
                            );
                            info!("Validated NextECashNoteIndex");
                        }
                        fedimint_mint_client::client_db::DbKeyPrefix::CancelledOOBSpend => {
                            let canceled_spend = dbtx
                                .find_by_prefix(&CancelledOOBSpendKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_cancel_spends = canceled_spend.len();
                            ensure!(
                                num_cancel_spends > 0,
                                "validate_migrations was not able to read any CancelledOOBSpendKeys"
                            );
                            info!("Validated CancelledOOBSpendKey");
                        }
                        fedimint_mint_client::client_db::DbKeyPrefix::RecoveryState => {
                            let restore_state = dbtx.get_value(&RecoveryStateKey).await;
                            ensure!(
                                restore_state.is_none(),
                                "validate_migrations expect the restore state to get deleted"
                            );
                            info!("Validated RecoveryState");
                        }
                        fedimint_mint_client::client_db::DbKeyPrefix::RecoveryFinalized => {
                            let recovery_finalized = dbtx.get_value(&RecoveryFinalizedKey).await;
                            ensure!(
                                recovery_finalized.is_some(),
                                "validate_migrations was not able to read any RecoveryFinalized"
                            );
                            info!("Validated RecoveryFinalized");
                        }
                        fedimint_mint_client::client_db::DbKeyPrefix::ReusedNoteIndices => {}
                        fedimint_mint_client::client_db::DbKeyPrefix::RecoveryStateV2 => {
                            // New prefix for slice-based recovery, no migration
                            // needed
                        }
                        fedimint_mint_client::client_db::DbKeyPrefix::ExternalReservedStart
                        | fedimint_mint_client::client_db::DbKeyPrefix::CoreInternalReservedEnd
                        | fedimint_mint_client::client_db::DbKeyPrefix::CoreInternalReservedStart =>
                            {}
                    }
                }

                Ok(())
            },
        )
        .await
    }
}
