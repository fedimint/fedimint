use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::{DummyConfigGenParams, LEGACY_HARDCODED_INSTANCE_ID_DUMMY};
use fedimint_dummy_server::DummyGen;
use fedimint_logging::TracingSetup;
use fedimint_testing::federation::FederationFixture;
use fedimint_testing::fixtures::test;

fn fixture() -> FederationFixture {
    let mod_id = LEGACY_HARDCODED_INSTANCE_ID_DUMMY;
    TracingSetup::default().init().unwrap();
    let params = DummyConfigGenParams {
        tx_fee: Amount::ZERO,
    };
    FederationFixture::new_with_peers(2)
        .with_module(mod_id, DummyClientGen, DummyGen, params)
        .with_primary_module(mod_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn can_print_and_send_money() {
    test(fixture(), |fed, client1| async move {
        let client2 = fed.new_client().await;

        client1.print_money(sats(1000)).await.unwrap();
        assert_eq!(client1.total_funds().await, sats(1000));

        let outpoint = client1.send_money(client2.account(), sats(250)).await;
        client2.receive_money(outpoint.unwrap()).await.unwrap();
        assert_eq!(client1.total_funds().await, sats(750));
        assert_eq!(client2.total_funds().await, sats(250));
    })
    .await
}
