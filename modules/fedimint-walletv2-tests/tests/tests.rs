use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use async_stream::stream;
use bitcoin::Amount;
use fedimint_client::ClientHandleArc;
use fedimint_client::db::DbKeyPrefix;
use fedimint_client::error::OperationLookupError;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use fedimint_core::task::{sleep, sleep_in_test};
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_eventlog::{Event, EventLogEntry, EventLogId};
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_walletv2_client::events::{
    ReceivePaymentEvent, ReceivePaymentUpdateEvent, SendPaymentEvent, SendPaymentStatus,
    SendPaymentUpdateEvent,
};
use fedimint_walletv2_client::{
    FinalSendOperationState, SendError, WalletClientInit, WalletClientModule,
};
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
            .send(
                address.clone(),
                Amount::from_sat(10_000),
                None,
                serde_json::Value::Null,
            )
            .await?;

        let state = client
            .get_first_module::<WalletClientModule>()?
            .await_final_send_operation_state(send_op)
            .await?;

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

#[tokio::test(flavor = "multi_thread")]
async fn send_to_a_mainnet_address_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    // A well-known mainnet P2PKH address. The federation runs on regtest.
    let mainnet_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse()?;

    assert_matches!(
        client
            .get_first_module::<WalletClientModule>()?
            .send(
                mainnet_address,
                Amount::from_sat(100_000),
                None,
                serde_json::Value::Null,
            )
            .await,
        Err(SendError::WrongNetwork)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_below_the_dust_limit_is_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();

    let address = bitcoin.get_new_address().await.as_unchecked().clone();

    assert_matches!(
        client
            .get_first_module::<WalletClientModule>()?
            .send(address, Amount::from_sat(1), None, serde_json::Value::Null)
            .await,
        Err(SendError::DustValue)
    );

    Ok(())
}

#[derive(Debug, Encodable, Decodable)]
struct FillerKey(u32);

#[derive(Debug, Encodable, Decodable)]
struct FillerValue(Vec<u8>);

impl_db_record!(
    key = FillerKey,
    value = FillerValue,
    db_prefix = DbKeyPrefix::UserData,
);

#[tokio::test(flavor = "multi_thread")]
async fn first_address_search_survives_concurrent_db_writes() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    // the in-memory database keeps no write history, so only RocksDB can fail
    // a commit this way
    let client = fed.new_client_rocksdb().await;

    // the writes have to land while the scanner's first address search runs,
    // and that search starts as soon as the module is initialized
    let db = client.db().clone();
    let value = FillerValue(vec![0xab; 64 * 1024]);

    // 8 MiB is twice the write history RocksDB keeps. the pauses keep the
    // short transactions other client tasks commit from spanning that history
    for index in 0..128u32 {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&FillerKey(index), &value).await;
        dbtx.commit_tx().await;
        sleep(Duration::from_millis(1)).await;
    }

    let wallet = client.get_first_module::<WalletClientModule>()?;
    let client_shutdown = client.task_group().make_handle().make_shutdown_rx();

    tokio::select! {
        address = wallet.receive() => info!("Received address {address}"),
        () = client_shutdown => {
            panic!("The client shut down before the output scanner stored an address index")
        }
    }

    Ok(())
}

mod db;

/// Awaiting an operation that was never started reports the shared
/// operation-lookup error, not an opaque one.
#[tokio::test(flavor = "multi_thread")]
async fn awaiting_an_unknown_send_operation_reports_not_found() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;

    assert_matches!(
        client
            .get_first_module::<WalletClientModule>()?
            .await_final_send_operation_state(OperationId::new_random())
            .await,
        Err(OperationLookupError::NotFound(_))
    );

    Ok(())
}
