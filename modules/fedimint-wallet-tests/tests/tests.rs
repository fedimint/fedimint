use std::time::SystemTime;

use bitcoin::Amount;
use fedimint_core::sats;
use fedimint_core::util::NextOrPending;
use fedimint_dummy_client::DummyClientGen;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_testing::fixtures::{Fixtures, TIMEOUT};
use fedimint_wallet_client::{DepositState, WalletClientExt, WalletClientGen};
use fedimint_wallet_common::config::WalletGenParams;
use fedimint_wallet_server::WalletGen;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(0, DummyClientGen, DummyGen, DummyGenParams::default());
    let wallet_params = WalletGenParams::regtest(fixtures.bitcoin_server());
    let wallet_client = WalletClientGen::new(fixtures.bitcoin_client());
    fixtures.with_module(1, wallet_client, WalletGen, wallet_params)
}

#[tokio::test(flavor = "multi_thread")]
async fn on_chain_deposits() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    let valid_until = SystemTime::now() + TIMEOUT;

    let (op, address) = client.get_deposit_address(valid_until).await?;
    bitcoin
        .send_and_mine_block(&address, Amount::from_sat(1000))
        .await;
    let sub = client.subscribe_deposit_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, DepositState::WaitingForTransaction);
    assert_eq!(sub.ok().await?, DepositState::WaitingForConfirmation);

    // Need to mine blocks until deposit is confirmed
    bitcoin.mine_blocks(finality_delay).await;
    assert_eq!(sub.ok().await?, DepositState::Confirmed);
    assert_eq!(sub.ok().await?, DepositState::Claimed);
    assert_eq!(client.get_balance().await, sats(1000));
    Ok(())
}
