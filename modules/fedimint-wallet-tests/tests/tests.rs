use std::time::SystemTime;

use fedimint_core::sats;
use fedimint_core::util::NextOrPending;
use fedimint_dummy_client::DummyClientGen;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_testing::fixtures::{Fixtures, TIMEOUT};
use fedimint_wallet_client::{DepositState, WalletClientExt, WalletClientGen, WithdrawState};
use fedimint_wallet_common::config::WalletGenParams;
use fedimint_wallet_server::WalletGen;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientGen, DummyGen, DummyGenParams::default());
    let wallet_params = WalletGenParams::regtest(fixtures.bitcoin_server());
    let wallet_client = WalletClientGen::new(fixtures.bitcoin_client());
    fixtures.with_module(wallet_client, WalletGen, wallet_params)
}

fn bsats(satoshi: u64) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(satoshi)
}

const PEG_IN_AMOUNT_SATS: u64 = 5000;
const PEG_OUT_AMOUNT_SATS: u64 = 1000;

#[tokio::test(flavor = "multi_thread")]
async fn on_chain_peg_in_and_peg_out() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    let valid_until = SystemTime::now() + TIMEOUT;

    let mut balance_sub = client.subscribe_balance_changes().await;
    assert_eq!(balance_sub.ok().await?, sats(0));

    let (op, address) = client.get_deposit_address(valid_until).await?;
    bitcoin
        .send_and_mine_block(&address, bsats(PEG_IN_AMOUNT_SATS))
        .await;
    let sub = client.subscribe_deposit_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, DepositState::WaitingForTransaction);
    assert_eq!(sub.ok().await?, DepositState::WaitingForConfirmation);

    // Need to mine blocks until deposit is confirmed
    bitcoin.mine_blocks(finality_delay).await;
    assert_eq!(sub.ok().await?, DepositState::Confirmed);
    assert_eq!(sub.ok().await?, DepositState::Claimed);
    assert_eq!(client.get_balance().await, sats(PEG_IN_AMOUNT_SATS));
    assert_eq!(balance_sub.ok().await?, sats(PEG_IN_AMOUNT_SATS));

    // Peg-out test, requires block to recognize change UTXOs
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);
    let fees = client.get_withdraw_fee(address.clone(), peg_out).await?;
    let op = client.withdraw(address.clone(), peg_out, fees).await?;

    let balance_after_peg_out =
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS - fees.amount().to_sat());
    assert_eq!(client.get_balance().await, balance_after_peg_out);
    assert_eq!(balance_sub.ok().await?, balance_after_peg_out);

    let sub = client.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    let txid = match sub.ok().await? {
        WithdrawState::Succeeded(txid) => txid,
        _ => panic!("Unexpected state"),
    };
    bitcoin.get_mempool_tx_fee(&txid).await;

    let received = bitcoin.mine_block_and_get_received(&address).await;
    assert_eq!(received, peg_out.into());
    Ok(())
}
