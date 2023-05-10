use fedimint_dummy_client::DummyClientGen;
use fedimint_dummy_common::config::DummyConfigGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{LightningClientExt, LightningClientGen};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_testing::fixtures::Fixtures;
use fedimint_wallet_client::WalletClientGen;
use fedimint_wallet_common::config::WalletGenParams;
use fedimint_wallet_tests::FakeWalletGen;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::default();
    let wallet_gen = FakeWalletGen::new(&fixtures);
    fixtures
        .with_primary(1, DummyClientGen, DummyGen, DummyConfigGenParams::default())
        .with_module(0, LightningClientGen, LightningGen, LightningGenParams)
        // TODO: Remove dependency on wallet
        .with_module(2, WalletClientGen, wallet_gen, WalletGenParams::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn can_switch_active_gateway() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed(2).await;
    let client = fed.new_client().await;
    let gateway1 = fixtures.new_gateway(vec![&fed]).await.last_registration();
    assert_eq!(client.select_active_gateway().await?, gateway1);

    let gateway2 = fixtures.new_gateway(vec![&fed]).await.last_registration();
    let gateways = client.fetch_registered_gateways().await.unwrap();
    assert_eq!(gateways.len(), 2);

    client.set_active_gateway(&gateway2.node_pub_key).await?;
    assert_eq!(client.select_active_gateway().await?, gateway2);
    Ok(())
}
