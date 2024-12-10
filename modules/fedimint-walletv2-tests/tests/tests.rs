use std::time::Duration;

use bitcoin::Amount;
use fedimint_client::ClientHandleArc;
use fedimint_core::task::sleep_in_test;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_testing::fixtures::Fixtures;
use fedimint_walletv2_client::{FinalOperationState, WalletClientInit, WalletClientModule};
use fedimint_walletv2_common::config::WalletGenParams;
use fedimint_walletv2_server::WalletInit;
use tracing::info;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());

    let wallet_params = WalletGenParams::regtest(fixtures.bitcoin_server());

    let wallet_client = WalletClientInit {
        esplora_connection: fixtures.dyn_esplora_connection(),
    };

    fixtures.with_module(wallet_client, WalletInit, wallet_params)
}

fn bsats(satoshi: u64) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(satoshi)
}

async fn await_consensus_block_count(
    client: &ClientHandleArc,
    block_count: u64,
) -> anyhow::Result<()> {
    loop {
        if client
            .get_first_module::<WalletClientModule>()?
            .consensus_block_count()
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

async fn await_pending_transaction_count(
    client: &ClientHandleArc,
    transaction_count: usize,
) -> anyhow::Result<()> {
    loop {
        if client
            .get_first_module::<WalletClientModule>()?
            .pending_transactions()
            .await?
            .len()
            == transaction_count
        {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for {transaction_count} transactions to become pending."),
            Duration::from_secs(1),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_send_and_receive() -> anyhow::Result<()> {
    let fixtures = fixtures();

    let fed = fixtures.new_default_fed().await;

    let client = fed.new_client().await;

    let bitcoin = fixtures.bitcoin();

    // We need the consensus block count to reach a non-zero value before we send in
    // any funds such that the UTXO is tracked by the federation.

    info!("Wait for the consensus to reach block count one");

    bitcoin.mine_blocks(1 + 6).await;

    await_consensus_block_count(&client, 1).await?;

    info!("Deposit funds into the federation...");

    let federation_address = client
        .get_first_module::<WalletClientModule>()?
        .derive_address(0);

    bitcoin
        .send_and_mine_block(&federation_address, bsats(100_000))
        .await;

    bitcoin
        .send_and_mine_block(&federation_address, bsats(200_000))
        .await;

    info!("Wait for the finality delay of six blocks...");

    let current_consensus = client
        .get_first_module::<WalletClientModule>()?
        .consensus_block_count()
        .await?;

    bitcoin.mine_blocks(6).await;

    await_consensus_block_count(&client, current_consensus + 6).await?;

    info!("Claim ecash for the second deposit...");

    let unspent_deposits = client
        .get_first_module::<WalletClientModule>()?
        .check_address_for_deposits(0, Some(fixtures.esplora_api()))
        .await?;

    assert_eq!(unspent_deposits.len(), 2);

    let receive_op = client
        .get_first_module::<WalletClientModule>()?
        .receive(&unspent_deposits[0], None)
        .await?;

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .await_final_operation_state(receive_op)
            .await,
        FinalOperationState::Success
    );

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .federation_value()
            .await?,
        bsats(200_000)
    );

    info!("Claim ecash for the first deposit...");

    let unspent_deposits = client
        .get_first_module::<WalletClientModule>()?
        .check_address_for_deposits(0, Some(fixtures.esplora_api()))
        .await?;

    assert_eq!(unspent_deposits.len(), 1);

    let receive_op = client
        .get_first_module::<WalletClientModule>()?
        .receive(&unspent_deposits[0], None)
        .await?;

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .await_final_operation_state(receive_op)
            .await,
        FinalOperationState::Success
    );

    assert!(
        client
            .get_first_module::<WalletClientModule>()?
            .federation_value()
            .await?
            >= bsats(295_000)
    );

    await_pending_transaction_count(&client, 1).await?;

    info!("Send ecash back on-chain...");

    let address = bitcoin.get_new_address().await;

    let send_op = client
        .get_first_module::<WalletClientModule>()?
        .send(address.as_unchecked(), bsats(250_000), None)
        .await?;

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .await_final_operation_state(send_op)
            .await,
        FinalOperationState::Success
    );

    assert!(
        client
            .get_first_module::<WalletClientModule>()?
            .federation_value()
            .await?
            < bsats(50_000)
    );

    await_pending_transaction_count(&client, 2).await?;

    loop {
        if bitcoin.mine_block_and_get_received(&address).await == bsats(250_000).into() {
            break;
        }

        sleep_in_test(
            "Waiting for the transactions to be confirmed by the receiver.",
            Duration::from_secs(1),
        )
        .await;
    }

    bitcoin.mine_blocks(6).await;

    await_pending_transaction_count(&client, 0).await
}

#[tokio::test(flavor = "multi_thread")]
async fn fee_exceeds_one_bitcoin_within_twenty_five_pending_transactions() -> anyhow::Result<()> {
    let fixtures = fixtures();

    let fed = fixtures.new_default_fed().await;

    let client = fed.new_client().await;

    let bitcoin = fixtures.bitcoin();

    // We need the consensus block count to reach a non-zero value before we send in
    // any funds such that the UTXO is tracked by the federation.

    info!("Wait for the consensus to reach block count one");

    bitcoin.mine_blocks(1 + 6).await;

    await_consensus_block_count(&client, 1).await?;

    info!("Deposit funds into the federation...");

    let federation_address = client
        .get_first_module::<WalletClientModule>()?
        .derive_address(0);

    bitcoin
        .send_and_mine_block(&federation_address, Amount::from_int_btc(100))
        .await;

    info!("Wait for the finality delay of six blocks...");

    let current_consensus = client
        .get_first_module::<WalletClientModule>()?
        .consensus_block_count()
        .await?;

    bitcoin.mine_blocks(6).await;

    await_consensus_block_count(&client, current_consensus + 6).await?;

    info!("Claim ecash for the deposit...");

    let unspent_deposits = client
        .get_first_module::<WalletClientModule>()?
        .check_address_for_deposits(0, Some(fixtures.esplora_api()))
        .await?;

    assert_eq!(unspent_deposits.len(), 1);

    let receive_op = client
        .get_first_module::<WalletClientModule>()?
        .receive(&unspent_deposits[0], None)
        .await?;

    assert_eq!(
        client
            .get_first_module::<WalletClientModule>()?
            .await_final_operation_state(receive_op)
            .await,
        FinalOperationState::Success
    );

    bitcoin.mine_blocks(6).await;

    await_pending_transaction_count(&client, 0).await?;

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
            .send(address.as_unchecked(), Amount::from_sat(10_000), None)
            .await?;

        assert_eq!(
            client
                .get_first_module::<WalletClientModule>()?
                .await_final_operation_state(send_op)
                .await,
            FinalOperationState::Success
        );
    }

    panic!("Transaction fee did not exceed one bitcoin")
}
