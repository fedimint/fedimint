use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use bitcoin::Amount;
use fedimint_client::ClientHandleArc;
use fedimint_core::task::sleep_in_test;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_walletv2_client::events::{
    ReceivePaymentEvent, ReceivePaymentUpdateEvent, SendPaymentEvent, SendPaymentStatus,
    SendPaymentUpdateEvent,
};
use fedimint_walletv2_client::{FinalSendOperationState, WalletClientInit, WalletClientModule};
use fedimint_walletv2_common::KIND;
use fedimint_walletv2_server::{CONFIRMATION_FINALITY_DELAY, WalletInit};
use futures::StreamExt;
use tracing::info;

#[derive(Debug)]
enum WalletEvent {
    Send(SendPaymentEvent),
    SendStatus(SendPaymentUpdateEvent),
    Receive(ReceivePaymentEvent),
    ReceiveStatus(ReceivePaymentUpdateEvent),
}

fn wallet_event_stream(client: &ClientHandleArc) -> impl futures::Stream<Item = WalletEvent> {
    let client = client.clone();
    let mut log_rx = client.log_event_added_rx();
    let mut next_id = EventLogId::LOG_START;

    stream! {
        loop {
            let events = client.get_event_log(Some(next_id), 100).await;

            for entry in events {
                next_id = entry.id().saturating_add(1);

                if let Some(event) = try_parse_wallet_event(entry.as_raw()) {
                    yield event;
                }
            }

            let _ = log_rx.changed().await;
        }
    }
}

fn try_parse_wallet_event(entry: &EventLogEntry) -> Option<WalletEvent> {
    if entry.module_kind() != Some(&KIND) {
        return None;
    }

    if entry.kind == SendPaymentEvent::KIND {
        return entry.to_event().map(WalletEvent::Send);
    }

    if entry.kind == SendPaymentUpdateEvent::KIND {
        return entry.to_event().map(WalletEvent::SendStatus);
    }

    if entry.kind == ReceivePaymentEvent::KIND {
        return entry.to_event().map(WalletEvent::Receive);
    }

    if entry.kind == ReceivePaymentUpdateEvent::KIND {
        return entry.to_event().map(WalletEvent::ReceiveStatus);
    }

    None
}

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit).with_module(WalletClientInit, WalletInit)
}

// We need the consensus block count to reach a non-zero value before we send in
// any funds such that the UTXO is tracked by the federation.
async fn initialize_consensus(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<()> {
    info!("Wait for the consensus to reach block count one");

    bitcoin.mine_blocks(1 + CONFIRMATION_FINALITY_DELAY).await;

    await_consensus_block_count(client, 1).await
}

async fn await_finality_delay(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<()> {
    info!("Wait for the finality delay of six blocks...");

    let current_consensus = client
        .get_first_module::<WalletClientModule>()?
        .block_count()
        .await?;

    bitcoin.mine_blocks(CONFIRMATION_FINALITY_DELAY).await;

    await_consensus_block_count(client, current_consensus + CONFIRMATION_FINALITY_DELAY).await
}

async fn await_consensus_block_count(
    client: &ClientHandleArc,
    block_count: u64,
) -> anyhow::Result<()> {
    loop {
        if client
            .get_first_module::<WalletClientModule>()?
            .block_count()
            .await?
            >= block_count
        {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for consensus to reach block count {block_count}"),
            Duration::from_secs(1),
        )
        .await;
    }
}

async fn await_federation_total_value(
    client: &ClientHandleArc,
    min_value: bitcoin::Amount,
) -> anyhow::Result<()> {
    loop {
        let current_value = client
            .get_first_module::<WalletClientModule>()?
            .total_value()
            .await?;

        if current_value >= min_value {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for federation total value of {current_value} to reach {min_value}"),
            Duration::from_secs(1),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_in_operation_fees() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    info!("Deposit funds into the federation...");

    let federation_address = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    bitcoin
        .send_and_mine_block(&federation_address, Amount::from_sat(100_000))
        .await;

    await_finality_delay(&client, &bitcoin).await?;

    info!("Wait for deposit to be auto-claimed...");

    await_federation_total_value(&client, Amount::from_sat(99_000)).await?;

    let mut events = pin!(wallet_event_stream(&client));

    let Some(WalletEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };

    let Some(WalletEvent::ReceiveStatus(_)) = events.next().await else {
        panic!("Expected ReceiveStatus event");
    };

    let operation_fees = client
        .get_operation_fees(receive.operation_id)
        .await
        .expect("Fee calculation should succeed for peg-in operations");

    assert!(
        operation_fees.is_final,
        "Peg-in operation should be final after receiving ReceiveStatus"
    );
    assert!(
        operation_fees.amount.get_bitcoin().msats > 0,
        "Peg-in fees should be non-zero"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_out_operation_fees() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    info!("Deposit funds into the federation...");

    let federation_address = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    bitcoin
        .send_and_mine_block(&federation_address, Amount::from_sat(1_000_000))
        .await;

    await_finality_delay(&client, &bitcoin).await?;
    await_federation_total_value(&client, Amount::from_sat(99_000)).await?;

    info!("Send funds out of the federation...");

    let address = bitcoin.get_new_address().await.as_unchecked().clone();

    let send_op = client
        .get_first_module::<WalletClientModule>()?
        .send(address, Amount::from_sat(50_000), None)
        .await?;

    let state = client
        .get_first_module::<WalletClientModule>()?
        .await_final_send_operation_state(send_op)
        .await;

    assert!(matches!(state, FinalSendOperationState::Success(_)));

    let operation_fees = client
        .get_operation_fees(send_op)
        .await
        .expect("Fee calculation should succeed for peg-out operations");

    assert!(
        operation_fees.is_final,
        "Peg-out operation should be final after success"
    );
    assert!(
        operation_fees.amount.get_bitcoin().msats > 0,
        "Peg-out fees should be non-zero"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fee_exceeds_one_bitcoin_with_many_pending_txs() -> anyhow::Result<()> {
    let fixtures = fixtures();

    let fed = fixtures.new_fed_not_degraded().await;

    let client = fed.new_client().await;

    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    info!("Deposit funds into the federation...");

    let federation_address = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    bitcoin
        .send_and_mine_block(&federation_address, Amount::from_int_btc(100))
        .await;

    await_finality_delay(&client, &bitcoin).await?;

    info!("Wait for deposit to be auto-claimed...");

    await_federation_total_value(&client, Amount::from_sat(99_000_000)).await?;

    let address = bitcoin.get_new_address().await.as_unchecked().clone();

    let mut events = pin!(wallet_event_stream(&client));

    let Some(WalletEvent::Receive(receive)) = events.next().await else {
        panic!("Expected Receive event");
    };

    let Some(WalletEvent::ReceiveStatus(status)) = events.next().await else {
        panic!("Expected ReceiveStatus event");
    };
    assert_eq!(status.operation_id, receive.operation_id);

    for _ in 0..19 {
        let send_fee = client
            .get_first_module::<WalletClientModule>()?
            .send_fee()
            .await?;

        if send_fee >= Amount::from_int_btc(1) {
            return Ok(());
        }

        let send_op = client
            .get_first_module::<WalletClientModule>()?
            .send(address.clone(), Amount::from_sat(10_000), None)
            .await?;

        let state = client
            .get_first_module::<WalletClientModule>()?
            .await_final_send_operation_state(send_op)
            .await;

        assert!(matches!(state, FinalSendOperationState::Success(_)));

        let Some(WalletEvent::Send(e)) = events.next().await else {
            panic!("Expected Send event");
        };
        assert_eq!(e.operation_id, send_op);

        let Some(WalletEvent::SendStatus(e)) = events.next().await else {
            panic!("Expected SendStatus event");
        };
        assert_eq!(e.operation_id, send_op);
        assert!(matches!(e.status, SendPaymentStatus::Success(_)));
    }

    panic!("Transaction fee did not exceed one bitcoin")
}
