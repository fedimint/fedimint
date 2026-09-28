use std::time::Duration;

use anyhow::ensure;
use assert_matches::assert_matches;
use bls12_381::G1Affine;
use fedimint_client::ClientHandleArc;
use fedimint_client::backup::{ClientBackup, Metadata};
use fedimint_client::transaction::{ClientInput, ClientInputBundle, TransactionBuilder};
use fedimint_client_module::ClientModule;
use fedimint_client_module::error::{OperationLookupError, TransactionSubmitError};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::task::sleep_in_test;
use fedimint_core::util::backoff_util::aggressive_backoff;
use fedimint_core::util::{FmtCompact as _, NextOrPending, retry};
use fedimint_core::{Amount, TieredMulti, sats, secp256k1};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_logging::LOG_TEST;
use fedimint_mint_client::api::MintFederationApi;
use fedimint_mint_client::client_db::{NextECashNoteIndexKey, NoteKey};
use fedimint_mint_client::{
    MintClientInit, MintClientModule, Note, OOBNotes, ReissueExternalNotesError,
    ReissueExternalNotesState, SelectNotesWithAtleastAmount, SelectNotesWithExactAmount,
    SpendOOBError, SpendOOBState, SpendableNote, SpendableNoteUndecoded,
    SubscribeReissueExternalNotesError, SubscribeSpendNotesError, ValidateNotesError,
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
        .spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            sats(750),
            Some(TIMEOUT),
            false,
            (),
        )
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

    let fees_from_balance = sats(750)
        .checked_sub(
            client2
                .get_balance_for_btc()
                .await
                .expect("Can fetch balance"),
        )
        .expect("Balance higher than received amount");
    let fees_from_operation = client2
        .get_operation_fees(op)
        .await
        .expect("Operation exists")
        .expect("Fee data is present for new operations");

    assert!(
        !client2.has_active_states(op).await,
        "We waited for operation completion, should be final"
    );
    assert_eq!(
        fees_from_balance,
        fees_from_operation.get_bitcoin(),
        "Operation fees differ from actual fees"
    );

    assert!(client1.get_balance_for_btc().await? >= sats(250).saturating_sub(EXPECTED_MAXIMUM_FEE));
    assert!(client2.get_balance_for_btc().await? >= sats(750).saturating_sub(EXPECTED_MAXIMUM_FEE));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reissue_fee_quote_matches_actual_fee() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (client_send, client_receive) = fed.two_clients().await;
    issue_ecash(&client_send, sats(11_000)).await?;

    // Reissue several times so the receiver's note inventory — and therefore the
    // consolidation-driven fee — differs between iterations (first into an empty
    // wallet, then into a progressively more populated one).
    for i in 0..5 {
        let send_mint = client_send.get_first_module::<MintClientModule>()?;
        let (spend_op, notes) = send_mint
            .spend_notes_with_selector(
                &SelectNotesWithAtleastAmount,
                sats(1_000),
                Some(TIMEOUT),
                false,
                (),
            )
            .await?;
        let mut send_sub = send_mint
            .subscribe_spend_notes(spend_op)
            .await?
            .into_stream();
        assert_eq!(send_sub.ok().await?, SpendOOBState::Created);

        let receive_mint = client_receive.get_first_module::<MintClientModule>()?;
        let reissued_value = notes.total_amount();

        let quote = receive_mint.reissue_fee_quote(&notes).await?;
        let before = client_receive.get_balance_for_btc().await?;

        let op = receive_mint.reissue_external_notes(notes, ()).await?;
        let mut sub = receive_mint
            .subscribe_reissue_external_notes(op)
            .await?
            .into_stream();
        assert_eq!(sub.ok().await?, ReissueExternalNotesState::Created);
        assert_eq!(sub.ok().await?, ReissueExternalNotesState::Issuing);
        // `Done` is reached once the reissued (and consolidation) notes have been
        // issued, so the balance is settled by here.
        assert_eq!(sub.ok().await?, ReissueExternalNotesState::Done);
        assert_eq!(send_sub.ok().await?, SpendOOBState::Success);

        let after = client_receive.get_balance_for_btc().await?;
        let actual_fee = reissued_value - (after - before);

        assert_eq!(
            quote.total(),
            Amounts::new_bitcoin(actual_fee),
            "iteration {i}: quoted fee {quote:?} != actual fee {actual_fee:?}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_fee_quote_matches_actual_fee() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    issue_ecash(&client, sats(11_000)).await?;

    // Send several times so the wallet's note inventory — and therefore whether a
    // self-reissue (and its fee) is needed to reach the requested denomination —
    // differs between iterations.
    for i in 0..5 {
        let mint = client.get_first_module::<MintClientModule>()?;

        // Settle any pending change from the previous iteration so the quote and
        // the send observe the same inventory.
        client.wait_for_all_active_state_machines().await;

        let quote = mint.send_fee_quote(sats(1_000)).await?;
        let before = client.get_balance_for_btc().await?;

        let notes = mint.send_oob_notes(sats(1_000), ()).await?;
        let sent_value = notes.total_amount();

        // A send may trigger an internal reissue whose change notes are credited
        // by output state machines; wait for them before reading the balance.
        client.wait_for_all_active_state_machines().await;
        let after = client.get_balance_for_btc().await?;

        // Value conservation: the wallet loses exactly the sent value plus the fee.
        let actual_fee = before - after - sent_value;

        assert_eq!(
            quote.total(),
            Amounts::new_bitcoin(actual_fee),
            "iteration {i}: quoted fee {quote:?} != actual fee {actual_fee:?}"
        );
    }

    Ok(())
}

/// An empty wallet cannot fund a send, and the fee quote says so with the
/// insufficient-funds condition rather than as a failure of the mint module,
/// which is what lets the "send everything" helpers probe a smaller amount.
#[tokio::test(flavor = "multi_thread")]
async fn send_fee_quote_without_funds_reports_insufficient_funds() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let mint = client.get_first_module::<MintClientModule>()?;

    assert_matches!(
        mint.send_fee_quote(sats(1_000)).await,
        Err(TransactionSubmitError::InsufficientFunds(_))
    );

    Ok(())
}

/// Regression test: a send that requires a self-reissue must succeed without
/// settling state machines between sends (as a wallet UI does).
///
/// Three 5,000,000 msat sends from a 20,000,000 msat balance. The first two are
/// served from exact change; the third can't make exact change and triggers a
/// self-reissue. Previously the reissue recursion ran before its freshly-minted
/// notes were spendable (it awaited only the *change* outputs), failed to make
/// exact change, re-reissued, and drained the wallet — surfacing as
/// "Failed to submit reissuance transaction: Insufficient balance" even though
/// the `send_fee_quote` had just succeeded.
#[tokio::test(flavor = "multi_thread")]
async fn send_oob_notes_reissue_without_settling() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    issue_ecash(&client, Amount::from_msats(20_000_000)).await?;

    for i in 0..3 {
        let mint = client.get_first_module::<MintClientModule>()?;
        // The quote must succeed (it always did); the send must succeed too.
        mint.send_fee_quote(Amount::from_msats(5_000_000)).await?;
        mint.send_oob_notes(Amount::from_msats(5_000_000), ())
            .await
            .map_err(|e| {
                anyhow::anyhow!("iteration {i}: send_oob_notes failed: {}", e.fmt_compact())
            })?;
    }

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

/// The single-peer nonce checks backing `mint dev check-nonce` and `mint dev
/// check-blind-nonce` have to agree with the threshold API, both before and
/// after the nonces are used.
#[tokio::test(flavor = "multi_thread")]
async fn single_peer_nonce_checks() -> anyhow::Result<()> {
    // Every peer has to be online, otherwise there is no answer to compare
    // against for the offline one.
    let fed = fixtures().new_fed_not_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    issue_ecash(&client1, sats(1000)).await?;

    let client1_mint = client1.get_first_module::<MintClientModule>()?;
    let client2_mint = client2.get_first_module::<MintClientModule>()?;
    let peers = client1_mint.api.all_peers().clone();

    let (_op, notes) = client1_mint
        .spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            sats(750),
            Some(TIMEOUT),
            false,
            (),
        )
        .await?;
    let nonces = notes
        .notes()
        .iter_items()
        .map(|(_, note)| note.nonce())
        .collect::<Vec<_>>();

    for &peer in &peers {
        for &nonce in &nonces {
            assert!(
                !client1_mint
                    .api
                    .check_note_spent_single_peer(peer, nonce)
                    .await?,
                "Peer {peer} should not consider the nonce spent yet"
            );
        }
    }

    let op = client2_mint.reissue_external_notes(notes, ()).await?;
    let mut sub = client2_mint
        .subscribe_reissue_external_notes(op)
        .await?
        .into_stream();
    assert_eq!(sub.ok().await?, ReissueExternalNotesState::Created);
    assert_eq!(sub.ok().await?, ReissueExternalNotesState::Issuing);
    assert_eq!(sub.ok().await?, ReissueExternalNotesState::Done);

    // A single peer can lag behind the threshold of peers that accepted the
    // transaction, so give each one a chance to catch up.
    for &peer in &peers {
        for &nonce in &nonces {
            retry(
                format!("waiting for peer {peer} to see the nonce as spent"),
                aggressive_backoff(),
                || async {
                    ensure!(
                        client1_mint
                            .api
                            .check_note_spent_single_peer(peer, nonce)
                            .await?,
                        "Peer {peer} does not consider the nonce spent yet"
                    );
                    Ok(())
                },
            )
            .await?;
        }
    }

    // Same for a blind nonce, which goes from unused to used once the output
    // creating it is accepted.
    let mut dbtx = client1_mint.db.begin_transaction().await;
    let operation_id = OperationId::new_random();
    let issuance_req = client1_mint
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

    for &peer in &peers {
        assert!(
            !client1_mint
                .api
                .check_blind_nonce_used_single_peer(peer, blind_nonce)
                .await?,
            "Peer {peer} should not consider the blind nonce used yet"
        );
    }

    let tx = TransactionBuilder::new().with_outputs(client1_mint.client_ctx.make_dyn(issuance_req));
    let change_range = client1_mint
        .client_ctx
        .finalize_and_submit_transaction(operation_id, "mint", |_| (), tx)
        .await?;
    client1.api().await_transaction(change_range.txid()).await;

    for &peer in &peers {
        retry(
            format!("waiting for peer {peer} to see the blind nonce as used"),
            aggressive_backoff(),
            || async {
                ensure!(
                    client1_mint
                        .api
                        .check_blind_nonce_used_single_peer(peer, blind_nonce)
                        .await?,
                    "Peer {peer} does not consider the blind nonce used yet"
                );
                Ok(())
            },
        )
        .await?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_blind_nonce_index_rejected() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    issue_ecash(&client, sats(1000)).await?;

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

    let duplicate_bundle = fedimint_client_module::transaction::ClientOutputBundle::new_no_sm(
        issuance_req.outputs().to_vec(),
    );
    let tx = TransactionBuilder::new()
        .with_outputs(client_mint.client_ctx.make_dyn(issuance_req))
        .with_outputs(client_mint.client_ctx.make_dyn(duplicate_bundle));

    let change_range = client_mint
        .client_ctx
        .finalize_and_submit_transaction(operation_id, "mint", |_| (), tx)
        .await?;

    let err = client
        .transaction_updates(operation_id)
        .await
        .await_tx_accepted(change_range.txid())
        .await
        .expect_err("transaction with duplicate blind nonce should be rejected");
    assert!(
        err.contains("blind nonce was already used"),
        "unexpected rejection: {err}"
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
        .await;

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
                        Some(ECASH_TIMEOUT),
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

#[allow(deprecated)]
#[tokio::test(flavor = "multi_thread")]
async fn backup_encode_decode_roundtrip() -> anyhow::Result<()> {
    // Give client initial balance
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let client_dummy_module = client.get_first_module::<DummyClientModule>()?;
    client_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

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

#[allow(deprecated)]
#[tokio::test(flavor = "multi_thread")]
async fn ecash_backup_can_recover_metadata() -> anyhow::Result<()> {
    // Give client initial balance
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let client_dummy_module = client.get_first_module::<DummyClientModule>()?;
    client_dummy_module
        .mock_receive(sats(1000), AmountUnit::BITCOIN)
        .await;

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
        .spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            sats(750),
            Some(TIMEOUT),
            false,
            (),
        )
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
async fn sends_ecash_out_of_band_no_timeout_finishes_without_refund() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    issue_ecash(&client, sats(1000)).await?;

    let mint_module = client.get_first_module::<MintClientModule>()?;
    let (op, _) = mint_module
        .spend_notes_with_selector(&SelectNotesWithAtleastAmount, sats(750), None, false, ())
        .await?;

    let sub = &mut mint_module.subscribe_spend_notes(op).await?.into_stream();
    assert_eq!(sub.ok().await?, SpendOOBState::Created);
    assert_eq!(sub.ok().await?, SpendOOBState::Success);

    Ok(())
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
            Some(TIMEOUT * 3),
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
        .await;

    // Spend from client1 to client2
    let err = client1
        .get_first_module::<MintClientModule>()?
        .spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            Amount::ZERO,
            Some(TIMEOUT),
            false,
            (),
        )
        .await
        .expect_err("Zero-amount spends should be forbidden");
    assert_matches!(err, SpendOOBError::ZeroAmount);

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
        .await;

    // Spend from client1 to client2
    let err = client1
        .get_first_module::<MintClientModule>()?
        .reissue_external_notes(
            OOBNotes::new(client1.federation_id().to_prefix(), Default::default()),
            (),
        )
        .await
        .expect_err("Zero-amount receives should be forbidden");
    assert_matches!(err, ReissueExternalNotesError::ZeroAmount);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reissuing_the_same_notes_twice_reports_already_reissued() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (client1, client2) = fed.two_clients().await;
    issue_ecash(&client1, sats(1000)).await?;

    let (_op, notes) = client1
        .get_first_module::<MintClientModule>()?
        .spend_notes_with_selector(&SelectNotesWithAtleastAmount, sats(500), None, false, ())
        .await?;

    let client2_mint = client2.get_first_module::<MintClientModule>()?;
    let op = client2_mint
        .reissue_external_notes(notes.clone(), ())
        .await?;
    assert_matches!(
        client2_mint
            .subscribe_reissue_external_notes(op)
            .await?
            .await_outcome()
            .await,
        Some(ReissueExternalNotesState::Done)
    );

    // The operation id is the hash of the notes, so a second reissue of the
    // same notes finds the existing operation instead of submitting again.
    assert_matches!(
        client2_mint.reissue_external_notes(notes, ()).await,
        Err(ReissueExternalNotesError::AlreadyReissued)
    );

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
                Some(TIMEOUT),
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

    // Check that a repair based on stale index candidates does not panic or
    // roll back an index that was concurrently advanced while repair was doing
    // federation API checks.
    {
        let mut dbtx = client_mint.db.begin_transaction().await;
        const TEST_NOTE_INDEX_KEY: NextECashNoteIndexKey =
            NextECashNoteIndexKey(Amount::from_msats(1));
        let old_nonce_index = dbtx
            .get_value(&TEST_NOTE_INDEX_KEY)
            .await
            .expect("Amount tier exists");
        let stale_nonce_index = old_nonce_index
            .checked_sub(1)
            .expect("Amount tier index was advanced");
        dbtx.insert_entry(&TEST_NOTE_INDEX_KEY, &stale_nonce_index)
            .await
            .expect("Failed to insert test note index");
        dbtx.commit_tx().await;

        let repair_fut = client_mint.try_repair_wallet(100);
        tokio::pin!(repair_fut);

        tokio::select! {
            biased;

            repair_result = &mut repair_fut => {
                panic!("Repair completed before concurrent index advance: {repair_result:?}");
            }
            () = tokio::task::yield_now() => {}
        }

        let concurrently_advanced_index = old_nonce_index + 1;
        let mut dbtx = client_mint.db.begin_transaction().await;
        dbtx.insert_entry(&TEST_NOTE_INDEX_KEY, &concurrently_advanced_index)
            .await
            .expect("Failed to concurrently advance test note index");
        dbtx.commit_tx().await;

        let repair_summary = repair_fut.await.expect("Repair should succeed");
        assert!(
            repair_summary.spent_notes.is_empty(),
            "No spent notes should be found"
        );
        let repaired_index = client_mint
            .db
            .begin_transaction_nc()
            .await
            .get_value(&TEST_NOTE_INDEX_KEY)
            .await
            .expect("Amount tier exists");
        assert!(
            concurrently_advanced_index <= repaired_index,
            "Repair should not roll back concurrently advanced index"
        );
        let repaired_indices = repair_summary.used_indices.get(Amount::from_msats(1)) as u64;
        assert!(
            repaired_indices <= repaired_index - concurrently_advanced_index,
            "Concurrently advanced stale index should not be counted as repaired"
        );
    }

    Ok(())
}

#[cfg(test)]
mod fedimint_migration_tests;

#[tokio::test(flavor = "multi_thread")]
async fn test_send_oob_notes() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;

    let client = fed.new_client().await;

    issue_ecash(&client, sats(10000)).await?;

    for _ in 0..21 {
        client
            .get_first_module::<MintClientModule>()?
            .send_oob_notes(Amount::from_sats(100), ())
            .await?;
    }

    Ok(())
}

/// A syntactically valid note. Its signature is never checked here: both the
/// cross-federation and unissued-tier checks in `validate_notes` return
/// before a note's signature is verified.
fn dummy_spendable_note() -> SpendableNote {
    const NOTE_HEX: &str = "a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f317\
        8fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553\
        207c8bd";

    SpendableNote::consensus_decode_hex(NOTE_HEX, &ModuleRegistry::default())
        .expect("hex note is well-formed")
}

#[tokio::test(flavor = "multi_thread")]
async fn validating_notes_from_another_federation_names_both_ids() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let mint_module = client.get_first_module::<MintClientModule>()?;

    let other = FederationId::dummy().to_prefix();
    let notes = OOBNotes::new(other, TieredMulti::default());

    let err = mint_module
        .validate_notes(&notes)
        .expect_err("Notes from another federation are not valid here");

    assert_matches!(err, ValidateNotesError::WrongFederationId { found, .. } if found == other);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn validating_a_note_of_an_unissued_tier_reports_the_tier() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let mint_module = client.get_first_module::<MintClientModule>()?;

    let amount = Amount::from_msats(7);
    let notes = OOBNotes::new(
        client.federation_id().to_prefix(),
        [(amount, dummy_spendable_note())].into_iter().collect(),
    );

    let err = mint_module
        .validate_notes(&notes)
        .expect_err("The federation does not issue this tier");

    assert_matches!(
        err,
        ValidateNotesError::InvalidAmountTier { amount: a, .. } if a == amount
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribing_to_an_unknown_operation_reports_not_found() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let client = fed.new_client().await;
    let mint = client.get_first_module::<MintClientModule>()?;
    let operation_id = OperationId::new_random();

    assert_matches!(
        mint.subscribe_reissue_external_notes(operation_id).await,
        Err(SubscribeReissueExternalNotesError::Operation(
            OperationLookupError::NotFound(_)
        ))
    );
    assert_matches!(
        mint.subscribe_spend_notes(operation_id).await,
        Err(SubscribeSpendNotesError::Operation(
            OperationLookupError::NotFound(_)
        ))
    );

    issue_ecash(&client, sats(1000)).await?;

    let (spend_op, notes) = mint
        .spend_notes_with_selector(&SelectNotesWithAtleastAmount, sats(500), None, false, ())
        .await?;

    // A spend operation is not a reissuance.
    assert_matches!(
        mint.subscribe_reissue_external_notes(spend_op).await,
        Err(SubscribeReissueExternalNotesError::NotAReissuance)
    );

    let reissue_op = mint.reissue_external_notes(notes, ()).await?;

    // A reissue operation is not an out-of-band spend.
    assert_matches!(
        mint.subscribe_spend_notes(reissue_op).await,
        Err(SubscribeSpendNotesError::NotAnOutOfBandSpend)
    );

    Ok(())
}
