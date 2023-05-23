use std::time::SystemTime;

use fedimint_dummy_client::DummyClientGen;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_testing::fixtures::{Fixtures, TIMEOUT};
use fedimint_wallet_client::{WalletClientExt, WalletClientGen};
use fedimint_wallet_common::config::WalletGenParams;
use fedimint_wallet_server::WalletGen;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(0, DummyClientGen, DummyGen, DummyGenParams::default());
    let wallet_params = WalletGenParams::regtest(fixtures.bitcoin_rpc());
    fixtures.with_module(1, WalletClientGen, WalletGen, wallet_params)
}

#[tokio::test(flavor = "multi_thread")]
async fn on_chain_deposits() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let valid_until = SystemTime::now() + TIMEOUT;

    let (_op, address) = client.get_deposit_address(valid_until).await?;
    bitcoin
        .send_and_mine_block(&address, bitcoin::Amount::from_sat(1000))
        .await;
    // TODO: Need to make the client not depend directly on esplora
    // let mut sub = client.subscribe_deposit_updates(op).await?;
    // assert_eq!(sub.ok().await?, DepositState::WaitingForTransaction);
    // assert_eq!(sub.ok().await?, DepositState::WaitingForConfirmation);
    Ok(())
}
