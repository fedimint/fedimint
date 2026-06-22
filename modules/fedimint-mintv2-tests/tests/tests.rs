use std::pin::pin;

use anyhow::ensure;
use async_stream::stream;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::transaction::TransactionBuilder;
use fedimint_client::{ClientHandleArc, RootSecret};
use fedimint_core::Amount;
use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::Amounts;
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_mintv2_client::{
    ECash, FinalReceiveOperationState, MintClientInit, MintClientModule, MintOperationMeta,
    ReceivePaymentEvent, ReceivePaymentStatus, ReceivePaymentUpdateEvent, SendPaymentEvent,
};
use fedimint_mintv2_common::KIND;
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
        let ecash = client_send
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
