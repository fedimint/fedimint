use std::pin::pin;

use anyhow::ensure;
use async_stream::stream;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::transaction::TransactionBuilder;
use fedimint_client::{ClientHandleArc, ModuleRecoveryCompleted, RootSecret};
use fedimint_core::Amount;
use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::Amounts;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_mintv2_client::{
    ECash, FinalReceiveOperationState, MintClientInit, MintClientModule, MintOperationMeta,
    ReceiveECashError, ReceivePaymentEvent, ReceivePaymentStatus, ReceivePaymentUpdateEvent,
    SendECashError, SendPaymentEvent, SpendableNote,
};
use fedimint_mintv2_common::{Denomination, KIND};
use fedimint_mintv2_server::MintInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use futures::StreamExt;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
enum MintEvent {
    Send(SendPaymentEvent),
    Receive(ReceivePaymentEvent),
    ReceiveUpdate(ReceivePaymentUpdateEvent),
}

fn mint_event_stream(client: &ClientHandleArc) -> impl futures::Stream<Item = MintEvent> {
    let client = client.clone();
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    stream! {
        loop {
            let events = client.get_event_log(Some(next_id), 100).await;

            for entry in events {
                next_id = entry.id().saturating_add(1);

                if let Some(event) = try_parse_mint_event(entry.as_raw()) {
                    yield event;
                }
            }

            let _ = log_rx.changed().await;
        }
    }
}

fn try_parse_mint_event(entry: &EventLogEntry) -> Option<MintEvent> {
    if entry.module_kind() != Some(&KIND) {
        return None;
    }

    if entry.kind == SendPaymentEvent::KIND {
        return entry.to_event().map(MintEvent::Send);
    }

    if entry.kind == ReceivePaymentUpdateEvent::KIND {
        return entry.to_event().map(MintEvent::ReceiveUpdate);
    }

    if entry.kind == ReceivePaymentEvent::KIND {
        return entry.to_event().map(MintEvent::Receive);
    }

    None
}

const SEND_SK: [u8; 64] = [0x42; 64];
const RECEIVE_SK: [u8; 64] = [0x69; 64];

fn root_secret(bytes: &[u8; 64]) -> RootSecret {
    RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(bytes))
}

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

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);

    fixtures.with_module(DummyClientInit, DummyInit)
}

#[tokio::test(flavor = "multi_thread")]
async fn send_and_receive() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client_send = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&SEND_SK))
        .await;

    let client_receive = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&RECEIVE_SK))
        .await;

    issue_ecash(&client_send, Amount::from_sats(11_000)).await?;

    let mut send_events = pin!(mint_event_stream(&client_send));
    let mut receive_events = pin!(mint_event_stream(&client_receive));

    for i in 0..10 {
        tracing::info!("Sending ecash payment {i} of 10");

        // Exercise both with and without the optional invite code.
        let include_invite = i % 2 == 0;

        let (operation_id, ecash) = client_send
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), Value::Null, include_invite)
            .await?;

        let Some(MintEvent::Send(send)) = send_events.next().await else {
            panic!("Expected Send event");
        };
        assert_eq!(send.operation_id, operation_id);

        let ecash = base32::encode_prefixed(FEDIMINT_PREFIX, &ecash);

        let ecash: ECash = base32::decode_prefixed(FEDIMINT_PREFIX, &ecash).unwrap();

        // When requested, the sender embeds the federation invite code so a
        // recipient can join the issuing federation directly from the received
        // ecash. Otherwise no invite is present.
        assert_eq!(
            ecash
                .federation_invite()
                .map(|invite| invite.federation_id()),
            include_invite.then(|| client_send.federation_id()),
        );

        let operation_id = client_receive
            .get_first_module::<MintClientModule>()?
            .receive(ecash, Value::Null)
            .await?;

        let state = client_receive
            .get_first_module::<MintClientModule>()?
            .await_final_receive_operation_state(operation_id)
            .await?;

        assert_eq!(state, FinalReceiveOperationState::Success);

        let Some(MintEvent::Receive(receive)) = receive_events.next().await else {
            panic!("Expected Receive event");
        };
        assert_eq!(receive.operation_id, operation_id);

        let Some(MintEvent::ReceiveUpdate(update)) = receive_events.next().await else {
            panic!("Expected ReceiveUpdate event");
        };
        assert_eq!(update.operation_id, receive.operation_id);
        assert_eq!(update.status, ReceivePaymentStatus::Success);

        test_client_recovery(&fed, &client_send, root_secret(&SEND_SK)).await?;
        test_client_recovery(&fed, &client_receive, root_secret(&RECEIVE_SK)).await?;
    }

    ensure!(client_receive.get_balance_for_btc().await? >= Amount::from_sats(9900));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_fee_quote_matches_actual_fee() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client_send = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&SEND_SK))
        .await;
    let client_receive = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&RECEIVE_SK))
        .await;

    issue_ecash(&client_send, Amount::from_sats(11_000)).await?;

    // Receive several times so the receiver's note inventory — and therefore the
    // rebalance-driven fee — differs between iterations (first into an empty
    // wallet, then into a progressively more populated one).
    for i in 0..5 {
        let (_operation_id, ecash) = client_send
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), Value::Null, false)
            .await?;
        let ecash: ECash = base32::decode_prefixed(
            FEDIMINT_PREFIX,
            &base32::encode_prefixed(FEDIMINT_PREFIX, &ecash),
        )
        .unwrap();

        let mint = client_receive.get_first_module::<MintClientModule>()?;
        let ecash_value = ecash.amount();

        let quote = mint.receive_fee_quote(&ecash).await?;
        let before = client_receive.get_balance_for_btc().await?;

        let operation_id = mint.receive(ecash, Value::Null).await?;
        let state = mint
            .await_final_receive_operation_state(operation_id)
            .await?;
        ensure!(state == FinalReceiveOperationState::Success);

        // The receive state machine reports `Success` once the tx is accepted,
        // but the reissued (change) notes are credited by the output state
        // machines. Wait for those before reading the settled balance.
        let MintOperationMeta::Receive {
            change_outpoint_range,
            ..
        } = client_receive
            .operation_log()
            .get_operation(operation_id)
            .await
            .expect("operation exists")
            .meta::<MintOperationMeta>()
        else {
            panic!("expected a receive operation");
        };
        client_receive
            .await_primary_bitcoin_module_outputs(
                operation_id,
                change_outpoint_range.into_iter().collect(),
            )
            .await?;

        let after = client_receive.get_balance_for_btc().await?;
        let actual_fee = ecash_value - (after - before);

        ensure!(
            quote.total() == Amounts::new_bitcoin(actual_fee),
            "iteration {i}: quoted fee {quote:?} != actual fee {actual_fee:?}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_fee_quote_matches_actual_fee() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&SEND_SK))
        .await;

    issue_ecash(&client, Amount::from_sats(11_000)).await?;

    // Send several times so the wallet's note inventory — and therefore whether a
    // self-reissue (and its fee) is needed to reach the requested denomination —
    // differs between iterations.
    for i in 0..5 {
        let mint = client.get_first_module::<MintClientModule>()?;

        // Settle any pending change from the previous iteration so the quote and
        // the send observe the same inventory.
        client.wait_for_all_active_state_machines().await?;

        let quote = mint.send_fee_quote(Amount::from_sats(1_000)).await?;
        let before = client.get_balance_for_btc().await?;

        let (_operation_id, ecash) = mint
            .send(Amount::from_sats(1_000), Value::Null, false)
            .await?;
        let sent_value = ecash.amount();

        // A send may trigger an internal reissue whose change notes are credited
        // by output state machines; wait for them before reading the balance.
        client.wait_for_all_active_state_machines().await?;
        let after = client.get_balance_for_btc().await?;

        // Value conservation: the wallet loses exactly the sent value plus the fee.
        let actual_fee = before - after - sent_value;

        ensure!(
            quote.total() == Amounts::new_bitcoin(actual_fee),
            "iteration {i}: quoted fee {quote:?} != actual fee {actual_fee:?}"
        );
    }

    Ok(())
}

/// Wait for and return the `amount` from the mintv2 module's
/// `ModuleRecoveryCompleted` event in `client`'s event log.
///
/// `ModuleRecoveryCompleted` is a core event (its module tag is unset), so
/// unlike `mint_event_stream` it's matched by event kind and by the mintv2
/// `kind` carried in the payload (recovery runs for the dummy module too).
///
/// Blocks until the event has been ordered into the log; it is emitted as
/// recovery finishes, so this returns shortly after `wait_for_all_recoveries`.
async fn mintv2_recovery_completed_amount(client: &ClientHandleArc) -> Option<Amount> {
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    loop {
        for entry in client.get_event_log(Some(next_id), 100).await {
            next_id = entry.id().saturating_add(1);

            if entry.as_raw().kind != ModuleRecoveryCompleted::KIND {
                continue;
            }

            let event: ModuleRecoveryCompleted = entry
                .as_raw()
                .to_event()
                .expect("recovery-completed payload must decode");

            if event.kind.as_ref() == Some(&KIND) {
                return event.amount;
            }
        }

        log_rx
            .changed()
            .await
            .expect("event log notifier stays alive while the client is running");
    }
}

async fn test_client_recovery(
    fed: &FederationTest,
    client: &ClientHandleArc,
    root_secret: RootSecret,
) -> anyhow::Result<()> {
    // Wait for state machines to complete
    client.wait_for_all_active_state_machines().await?;

    let expected_balance = client.get_balance_for_btc().await?;

    assert_ne!(expected_balance, Amount::ZERO);

    let recovering_client = fed
        .recover_client_with_db(MemDatabase::new().into(), root_secret.clone())
        .await;

    recovering_client.wait_for_all_recoveries().await?;

    // The mintv2 module's recovery-completed event reports the total value of
    // the notes it reconstructed, which equals the pre-recovery balance.
    let event_amount = mintv2_recovery_completed_amount(&recovering_client).await;
    ensure!(
        event_amount == Some(expected_balance),
        "recovery-completed event amount mismatch: expected {expected_balance}, got {event_amount:?}"
    );

    // After recovery completes, we need to reopen the client for modules to be
    // available. This is documented behavior - see gateway's client.rs:94-97
    let recovered_client = fed
        .open_client_with_db(recovering_client.db().clone(), root_secret)
        .await;

    recovered_client
        .wait_for_all_active_state_machines()
        .await?;

    let recovered_balance = recovered_client.get_balance_for_btc().await?;

    ensure!(
        recovered_balance == expected_balance,
        "Recovery balance mismatch: expected {expected_balance}, got {recovered_balance}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn double_spend_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let (client_send, client_receive) = fed.two_clients().await;

    issue_ecash(&client_send, Amount::from_sats(10_000)).await?;

    let mut send_events = pin!(mint_event_stream(&client_send));
    let mut receive_events = pin!(mint_event_stream(&client_receive));

    let (send_operation_id, ecash) = client_send
        .get_first_module::<MintClientModule>()?
        .send(Amount::from_sats(1_000), Value::Null, false)
        .await?;

    let Some(MintEvent::Send(send)) = send_events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, send_operation_id);

    let operation_id = client_send
        .get_first_module::<MintClientModule>()?
        .receive(ecash.clone(), Value::Null)
        .await?;

    let state = client_send
        .get_first_module::<MintClientModule>()?
        .await_final_receive_operation_state(operation_id)
        .await?;

    assert_eq!(state, FinalReceiveOperationState::Success);

    let Some(MintEvent::Receive(receive)) = send_events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    let Some(MintEvent::ReceiveUpdate(update)) = send_events.next().await else {
        panic!("Expected ReceiveUpdate event");
    };
    assert_eq!(update.operation_id, receive.operation_id);
    assert_eq!(update.status, ReceivePaymentStatus::Success);

    let operation_id = client_receive
        .get_first_module::<MintClientModule>()?
        .receive(ecash, Value::Null)
        .await?;

    let state = client_receive
        .get_first_module::<MintClientModule>()?
        .await_final_receive_operation_state(operation_id)
        .await?;

    assert_eq!(state, FinalReceiveOperationState::Rejected);

    let Some(MintEvent::Receive(receive)) = receive_events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    let Some(MintEvent::ReceiveUpdate(update)) = receive_events.next().await else {
        panic!("Expected ReceiveUpdate event");
    };
    assert_eq!(update.operation_id, receive.operation_id);
    assert_eq!(update.status, ReceivePaymentStatus::Rejected);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_with_invalid_signature_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client = fed.new_client().await;

    issue_ecash(&client, Amount::from_sats(10_000)).await?;

    let mut events = pin!(mint_event_stream(&client));

    let (operation_id, ecash) = client
        .get_first_module::<MintClientModule>()?
        .send(Amount::from_sats(1_000), Value::Null, false)
        .await?;

    let Some(MintEvent::Send(send)) = events.next().await else {
        panic!("Expected Send event");
    };
    assert_eq!(send.operation_id, operation_id);

    let mut invalid_notes = ecash.notes();

    for note in &mut invalid_notes {
        note.signature = tbs::Signature(bls12_381::G1Affine::generator());
    }

    let invalid_ecash = ECash::new(ecash.mint().unwrap(), invalid_notes);

    let operation_id = client
        .get_first_module::<MintClientModule>()?
        .receive(invalid_ecash, Value::Null)
        .await?;

    let state = client
        .get_first_module::<MintClientModule>()?
        .await_final_receive_operation_state(operation_id)
        .await?;

    assert_eq!(state, FinalReceiveOperationState::Rejected);

    let Some(MintEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    let Some(MintEvent::ReceiveUpdate(update)) = events.next().await else {
        panic!("Expected ReceiveUpdate event");
    };
    assert_eq!(update.operation_id, receive.operation_id);
    assert_eq!(update.status, ReceivePaymentStatus::Rejected);

    let valid_ecash = ECash::new(ecash.mint().unwrap(), ecash.notes());

    let operation_id = client
        .get_first_module::<MintClientModule>()?
        .receive(valid_ecash, Value::Null)
        .await?;

    let state = client
        .get_first_module::<MintClientModule>()?
        .await_final_receive_operation_state(operation_id)
        .await?;

    assert_eq!(state, FinalReceiveOperationState::Success);

    let Some(MintEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };
    assert_eq!(receive.operation_id, operation_id);

    let Some(MintEvent::ReceiveUpdate(update)) = events.next().await else {
        panic!("Expected ReceiveUpdate event");
    };
    assert_eq!(update.operation_id, receive.operation_id);
    assert_eq!(update.status, ReceivePaymentStatus::Success);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_rejects_ecash_from_another_federation() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    issue_ecash(&client, Amount::from_sats(10_000)).await?;

    let (_operation_id, ecash) = client
        .get_first_module::<MintClientModule>()?
        .send(Amount::from_sats(1_000), Value::Null, false)
        .await?;

    // Re-wrap the same notes under a federation id that is not ours. `receive`
    // checks the mint id before submitting anything to consensus.
    let foreign_ecash = ECash::new(FederationId::dummy(), ecash.notes());

    assert_eq!(
        client
            .get_first_module::<MintClientModule>()?
            .receive(foreign_ecash, Value::Null)
            .await,
        Err(ReceiveECashError::WrongFederation),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receiving_the_same_ecash_twice_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    issue_ecash(&client, Amount::from_sats(10_000)).await?;

    let (_operation_id, ecash) = client
        .get_first_module::<MintClientModule>()?
        .send(Amount::from_sats(1_000), Value::Null, false)
        .await?;

    let operation_id = client
        .get_first_module::<MintClientModule>()?
        .receive(ecash.clone(), Value::Null)
        .await?;

    assert_eq!(
        client
            .get_first_module::<MintClientModule>()?
            .await_final_receive_operation_state(operation_id)
            .await?,
        FinalReceiveOperationState::Success,
    );

    // The operation id is derived from the ecash itself, so a second receive of
    // the identical notes finds the existing operation and refuses rather than
    // submitting a duplicate transaction.
    assert_eq!(
        client
            .get_first_module::<MintClientModule>()?
            .receive(ecash, Value::Null)
            .await,
        Err(ReceiveECashError::AlreadyReceived),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_rejects_notes_below_the_base_fee() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    // `Denomination(0)` is one msat, far below the hundred-msat base fee, so
    // reissuing it could never pay for itself. The signature is never checked
    // because the denomination guard runs first.
    let dust_note = SpendableNote {
        denomination: Denomination(0),
        keypair: Keypair::from_seckey_slice(SECP256K1, &[1u8; 32])?,
        signature: tbs::Signature(bls12_381::G1Affine::generator()),
    };

    let dust_ecash = ECash::new(client.federation_id(), vec![dust_note]);

    assert_eq!(
        client
            .get_first_module::<MintClientModule>()?
            .receive(dust_ecash, Value::Null)
            .await,
        Err(ReceiveECashError::UneconomicalDenomination),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_without_funds_reports_insufficient_balance() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    // Deliberately no `issue_ecash` call: the wallet is empty.
    let client = fed.new_client().await;

    assert_eq!(
        client
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), Value::Null, false)
            .await
            .map(|(_operation_id, ecash)| ecash.amount()),
        Err(SendECashError::InsufficientBalance),
    );

    Ok(())
}

mod db {
    use std::collections::{BTreeMap, BTreeSet};

    use anyhow::{Context, ensure};
    use bitcoin_hashes::{Hash as _, hash160};
    use bls12_381::G1Affine;
    use fedimint_client::module_init::DynClientModuleInit;
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKeyV0, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::secp256k1::{Keypair, SECP256K1};
    use fedimint_core::{OutPoint, TransactionId};
    use fedimint_logging::TracingSetup;
    use fedimint_mintv2_client::client_db::{
        self, RecoveryState, RecoveryStateKey, SpendableNoteKey, SpendableNotePrefix,
    };
    use fedimint_mintv2_client::issuance::NoteIssuanceRequest;
    use fedimint_mintv2_common::{MintCommonInit, RecoveryItem};
    use fedimint_mintv2_server::db::{
        BlindedSignatureShareKey, BlindedSignatureSharePrefix, BlindedSignatureShareRecoveryKey,
        BlindedSignatureShareRecoveryPrefix, DbKeyPrefix, IssuanceCounterKey,
        IssuanceCounterPrefix, NonceKey, NonceKeyPrefix, RecoveryItemKey, RecoveryItemPrefix,
    };
    use fedimint_server_core::DynServerModuleInit;
    use fedimint_testing::db::{
        BYTE_32, snapshot_db_migrations, snapshot_db_migrations_client, validate_migrations_client,
        validate_migrations_server,
    };
    use futures::StreamExt;
    use strum::IntoEnumIterator;
    use tbs::{BlindedMessage, BlindedSignatureShare, BlindingKey};

    use crate::{Denomination, MintClientInit, MintClientModule, MintInit, SpendableNote};

    /// The denomination every seeded record is filed under, so the validation
    /// closure can look the records back up by an exact key.
    const DENOMINATION: Denomination = Denomination(10);

    /// A keypair derived from a repeated byte, so the snapshot is reproducible.
    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32])
            .expect("a repeated non-zero byte is a valid secret key")
    }

    /// The transaction id every seeded record refers to. Nothing in these tests
    /// looks the transaction up, it only has to survive a database round-trip.
    fn txid() -> TransactionId {
        TransactionId::from_slice(&BYTE_32).expect("BYTE_32 is 32 bytes long")
    }

    /// A note that is only well-formed enough to survive a database round-trip;
    /// the signature is not a valid threshold signature over the nonce.
    fn spendable_note(seed: u8) -> SpendableNote {
        SpendableNote {
            denomination: DENOMINATION,
            keypair: keypair(seed),
            signature: tbs::Signature(G1Affine::generator()),
        }
    }

    fn issuance_request(seed: u8) -> NoteIssuanceRequest {
        NoteIssuanceRequest {
            denomination: DENOMINATION,
            tweak: [seed; 16],
            keypair: keypair(seed),
            blinding_key: BlindingKey(bls12_381::Scalar::from(u64::from(seed) + 1)),
        }
    }

    fn nonce_hash(seed: u8) -> hash160::Hash {
        hash160::Hash::hash(&[seed; 32])
    }

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only intended to
    /// provide coverage when reading the database in future code versions. This
    /// function should not be updated when database keys or values change -
    /// instead a new function should be added that creates a new database
    /// backup that can be tested.
    ///
    /// mintv2 has no server migrations yet, so what the paired test asserts is
    /// that every one of these rows still decodes under current code.
    async fn create_server_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&NonceKey(keypair(1).public_key()), &())
            .await;

        dbtx.insert_new_entry(
            &BlindedSignatureShareKey(OutPoint {
                txid: txid(),
                out_idx: 0,
            }),
            &BlindedSignatureShare(G1Affine::generator()),
        )
        .await;

        dbtx.insert_new_entry(
            &BlindedSignatureShareRecoveryKey(BlindedMessage(G1Affine::generator())),
            &BlindedSignatureShare(G1Affine::generator()),
        )
        .await;

        dbtx.insert_new_entry(&IssuanceCounterKey(DENOMINATION), &7)
            .await;

        // Both variants, since they encode differently and a change to either
        // would only show up if both are on disk.
        dbtx.insert_new_entry(
            &RecoveryItemKey(0),
            &RecoveryItem::Output {
                denomination: DENOMINATION,
                nonce_hash: nonce_hash(1),
                tweak: [1; 16],
            },
        )
        .await;

        dbtx.insert_new_entry(
            &RecoveryItemKey(1),
            &RecoveryItem::Input {
                nonce_hash: nonce_hash(2),
            },
        )
        .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, MintCommonInit>("mintv2-server-v0", |db| {
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

        validate_migrations_server(module, "mintv2-server", |db| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            // Matching every variant explicitly, with no catch-all, is the point of this
            // pattern: adding a new prefix breaks the build here until someone decides
            // how the migration test should cover it.
            for prefix in DbKeyPrefix::iter() {
                match prefix {
                    DbKeyPrefix::NoteNonce => {
                        let nonces = dbtx
                            .find_by_prefix(&NonceKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            nonces.len() == 1,
                            "the seeded spent nonce must still decode, got {} entries",
                            nonces.len()
                        );
                        ensure!(
                            nonces[0].0.0 == keypair(1).public_key(),
                            "the nonce must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::BlindedSignatureShare => {
                        let shares = dbtx
                            .find_by_prefix(&BlindedSignatureSharePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            shares.len() == 1,
                            "the seeded signature share must still decode, got {} entries",
                            shares.len()
                        );
                        ensure!(
                            shares[0].1 == BlindedSignatureShare(G1Affine::generator()),
                            "the signature share must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::BlindedSignatureShareRecovery => {
                        let shares = dbtx
                            .find_by_prefix(&BlindedSignatureShareRecoveryPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            shares.len() == 1,
                            "the seeded recovery signature share must still decode, got {} \
                             entries",
                            shares.len()
                        );
                        ensure!(
                            shares[0].0.0 == BlindedMessage(G1Affine::generator()),
                            "the blinded message key must round-trip unchanged"
                        );
                    }
                    DbKeyPrefix::MintAuditItem => {
                        let counter = dbtx
                            .get_value(&IssuanceCounterKey(DENOMINATION))
                            .await
                            .context("the seeded issuance counter must still decode")?;

                        ensure!(
                            counter == 7,
                            "the issuance counter must round-trip unchanged, got {counter}"
                        );

                        let counters = dbtx
                            .find_by_prefix(&IssuanceCounterPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            counters.len() == 1,
                            "exactly one denomination was seeded, got {} entries",
                            counters.len()
                        );
                    }
                    DbKeyPrefix::RecoveryItem => {
                        let items = dbtx
                            .find_by_prefix(&RecoveryItemPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;

                        ensure!(
                            items.len() == 2,
                            "both seeded recovery items must still decode, got {} entries",
                            items.len()
                        );
                        ensure!(
                            items[0].1
                                == RecoveryItem::Output {
                                    denomination: DENOMINATION,
                                    nonce_hash: nonce_hash(1),
                                    tweak: [1; 16],
                                },
                            "the output recovery item must round-trip unchanged"
                        );
                        ensure!(
                            items[1].1
                                == RecoveryItem::Input {
                                    nonce_hash: nonce_hash(2),
                                },
                            "the input recovery item must round-trip unchanged"
                        );
                    }
                }
            }

            Ok(())
        })
        .await
    }

    /// The client-side counterpart of `create_server_db_with_v0_data`, seeding
    /// the module's isolated namespace.
    async fn create_client_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`.
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&SpendableNoteKey(spendable_note(1)), &())
            .await;

        dbtx.insert_new_entry(
            &RecoveryStateKey,
            &RecoveryState {
                next_index: 3,
                total_items: 10,
                requests: BTreeMap::from([(nonce_hash(1), issuance_request(1))]),
                nonces: BTreeSet::from([nonce_hash(2)]),
            },
        )
        .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, MintCommonInit>(
            "mintv2-client-v0",
            |db| Box::pin(async { create_client_db_with_v0_data(db).await }),
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
            "mintv2-client",
            |db, _, _| async move {
                let mut dbtx = db.begin_transaction_nc().await;

                for prefix in client_db::DbKeyPrefix::iter() {
                    match prefix {
                        client_db::DbKeyPrefix::Note => {
                            let notes = dbtx
                                .find_by_prefix(&SpendableNotePrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;

                            ensure!(
                                notes.len() == 1,
                                "the seeded spendable note must still decode, got {} entries",
                                notes.len()
                            );
                            ensure!(
                                notes[0].0.0 == spendable_note(1),
                                "the spendable note must round-trip unchanged"
                            );
                        }
                        client_db::DbKeyPrefix::RecoveryState => {
                            let state = dbtx
                                .get_value(&RecoveryStateKey)
                                .await
                                .context("the seeded recovery state must still decode")?;

                            ensure!(
                                state.next_index == 3 && state.total_items == 10,
                                "the recovery progress must round-trip unchanged, got {}/{}",
                                state.next_index,
                                state.total_items
                            );
                            ensure!(
                                state.requests
                                    == BTreeMap::from([(nonce_hash(1), issuance_request(1))]),
                                "the pending issuance requests must round-trip unchanged"
                            );
                            ensure!(
                                state.nonces == BTreeSet::from([nonce_hash(2)]),
                                "the seen nonces must round-trip unchanged"
                            );
                        }
                    }
                }

                Ok(())
            },
        )
        .await
    }
}
