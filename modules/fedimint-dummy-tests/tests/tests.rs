use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::DummyConfigGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_testing::federation::FederationFixture;
use fedimint_testing::fixtures::test;

fn fixture() -> FederationFixture {
    let params = DummyConfigGenParams {
        tx_fee: Amount::ZERO,
    };
    FederationFixture::new_with_peers(2)
        .with_module(0, DummyClientGen, DummyGen, params)
        .with_primary_module(0)
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

#[tokio::test(flavor = "multi_thread")]
async fn can_threshold_sign_message() {
    test(fixture(), |_fed, client| async move {
        let message = "Hello fed!";
        let sig = client.fed_signature(message).await.unwrap();
        assert!(client.fed_public_key().verify(&sig, message));
    })
    .await
}
