use std::sync::Arc;
use std::time::Duration;

use bitcoin::Amount;
use fedimint_client::ClientHandleArc;
use fedimint_core::task::sleep_in_test;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_walletv2_client::{FinalSendOperationState, WalletClientInit, WalletClientModule};
use fedimint_walletv2_server::WalletInit;
use tracing::info;

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientInit, DummyInit).with_module(WalletClientInit, WalletInit)
}

fn bsats(satoshi: u64) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(satoshi)
}

// We need the consensus block count to reach a non-zero value before we send in
// any funds such that the UTXO is tracked by the federation.
async fn initialize_consensus(
    client: &ClientHandleArc,
    bitcoin: &Arc<dyn BitcoinTest>,
) -> anyhow::Result<()> {
    info!("Wait for the consensus to reach block count one");

    bitcoin.mine_blocks(1 + 6).await;

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

    bitcoin.mine_blocks(6).await;

    await_consensus_block_count(client, current_consensus + 6).await
}

async fn await_client_balance(
    client: &ClientHandleArc,
    min_balance: bitcoin::Amount,
) -> anyhow::Result<()> {
    loop {
        let balance = client.get_balance_for_btc().await?;

        if balance >= min_balance.into() {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for client balance ({balance}) to reach {min_balance}"),
            Duration::from_secs(1),
        )
        .await;
    }
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
async fn test_send_and_receive() -> anyhow::Result<()> {
    let fixtures = fixtures();

    let fed = fixtures.new_fed_not_degraded().await;

    let client = fed.new_client().await;

    let bitcoin = fixtures.bitcoin();

    initialize_consensus(&client, &bitcoin).await?;

    info!("Deposit funds into the federation...");

    let federation_address_1 = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    bitcoin
        .send_and_mine_block(&federation_address_1, bsats(100_000))
        .await;

    bitcoin
        .send_and_mine_block(&federation_address_1, bsats(200_000))
        .await;

    await_finality_delay(&client, &bitcoin).await?;

    info!("Wait for deposits to be auto-claimed...");

    await_federation_total_value(&client, bsats(290_000)).await?;

    await_client_balance(&client, bsats(290_000)).await?;

    let federation_address_2 = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    assert_ne!(federation_address_1, federation_address_2);

    bitcoin
        .send_and_mine_block(&federation_address_2, bsats(300_000))
        .await;

    bitcoin
        .send_and_mine_block(&federation_address_2, bsats(400_000))
        .await;

    await_finality_delay(&client, &bitcoin).await?;

    info!("Wait for deposits to be auto-claimed...");

    await_federation_total_value(&client, bsats(980_000)).await?;

    await_client_balance(&client, bsats(980_000)).await?;

    let federation_address_3 = client
        .get_first_module::<WalletClientModule>()?
        .receive()
        .await;

    assert_ne!(federation_address_2, federation_address_3);

    info!("Send ecash back on-chain...");

    let address = bitcoin.get_new_address().await;

    let send_op = client
        .get_first_module::<WalletClientModule>()?
        .send(address.as_unchecked().clone(), bsats(500_000), None)
        .await?;

    let FinalSendOperationState::Success(txid) = client
        .get_first_module::<WalletClientModule>()?
        .await_final_send_operation_state(send_op)
        .await
    else {
        panic!("Send operation failed");
    };

    loop {
        if bitcoin.get_mempool_tx(&txid).await.is_some() {
            break;
        }

        sleep_in_test("Waiting for tx in mempool", Duration::from_secs(1)).await;
    }

    assert!(
        client
            .get_first_module::<WalletClientModule>()?
            .total_value()
            .await?
            < bsats(500_000)
    );

    loop {
        if bitcoin.mine_block_and_get_received(&address).await == bsats(500_000).into() {
            break;
        }

        sleep_in_test(
            "Waiting for the transactions to be confirmed by the receiver.",
            Duration::from_secs(1),
        )
        .await;
    }

    info!("Verify that a send with zero fee aborts...");

    let address = bitcoin.get_new_address().await;

    let send_op = client
        .get_first_module::<WalletClientModule>()?
        .send(
            address.as_unchecked().clone(),
            bsats(100_000),
            Some(bsats(0)),
        )
        .await?;

    assert!(matches!(
        client
            .get_first_module::<WalletClientModule>()?
            .await_final_send_operation_state(send_op)
            .await,
        FinalSendOperationState::Aborted
    ));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fee_exceeds_one_bitcoin_within_twenty_five_pending_transactions() -> anyhow::Result<()> {
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

    bitcoin.mine_blocks(6).await;

    let address = bitcoin.get_new_address().await;

    for _ in 0..25 {
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
                address.as_unchecked().clone(),
                Amount::from_sat(10_000),
                None,
            )
            .await?;

        assert!(matches!(
            client
                .get_first_module::<WalletClientModule>()?
                .await_final_send_operation_state(send_op)
                .await,
            FinalSendOperationState::Success(_)
        ));
    }

    panic!("Transaction fee did not exceed one bitcoin")
}
