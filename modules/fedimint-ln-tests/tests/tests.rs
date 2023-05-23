use assert_matches::assert_matches;
use fedimint_client::Client;
use fedimint_core::sats;
use fedimint_core::util::NextOrPending;
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{LightningClientExt, LightningClientGen, LnPayState, LnReceiveState};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_mint_client::MintClientGen;
use fedimint_mint_common::config::MintGenParams;
use fedimint_mint_server::MintGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::GatewayTest;

fn fixtures() -> Fixtures {
    // TODO: Remove dependency on mint (legacy gw client)
    let fixtures = Fixtures::new_primary(1, MintClientGen, MintGen, MintGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_rpc());
    fixtures
        .with_module(3, DummyClientGen, DummyGen, DummyGenParams::default())
        .with_module(0, LightningClientGen, LightningGen, ln_params)
}

/// Setup a gateway connected to the fed and client
async fn gateway(fixtures: &Fixtures, fed: &FederationTest, client: &Client) -> GatewayTest {
    let gateway = fixtures.new_connected_gateway(fed).await;
    let node_pub_key = gateway.last_registered().await.node_pub_key;
    client.set_active_gateway(&node_pub_key).await.unwrap();
    gateway
}

#[tokio::test(flavor = "multi_thread")]
async fn can_switch_active_gateway() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;

    // Client selects a gateway by default
    let gateway1 = fixtures
        .new_connected_gateway(&fed)
        .await
        .last_registered()
        .await;
    assert_eq!(client.select_active_gateway().await?, gateway1);

    let gateway2 = fixtures
        .new_connected_gateway(&fed)
        .await
        .last_registered()
        .await;
    let gateways = client.fetch_registered_gateways().await.unwrap();
    assert_eq!(gateways.len(), 2);

    client.set_active_gateway(&gateway2.node_pub_key).await?;
    assert_eq!(client.select_active_gateway().await?, gateway2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn makes_internal_payments_within_gateway() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let _gateway = gateway(&fixtures, &fed, &client1).await;

    // Print money for client2
    let (op, outpoint) = client2.print_money(sats(1000)).await?;
    client2.await_primary_module_output(op, outpoint).await?;

    let (op, invoice) = client1
        .create_bolt11_invoice(sats(250), "description".to_string(), None)
        .await?;
    let mut sub1 = client1.subscribe_ln_receive(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, LnReceiveState::Created);
    assert_matches!(sub1.ok().await?, LnReceiveState::WaitingForPayment { .. });

    let op = client2.pay_bolt11_invoice(invoice).await?;
    let mut sub2 = client2.subscribe_ln_pay(op).await?.into_stream();
    assert_eq!(sub2.ok().await?, LnPayState::Created);
    // TODO: Finish after gw moves from legacy client
    // assert_eq!(next(sub2).await, LnPayState::Funded);
    // assert_matches!(next(sub2).await, LnPayState::Success{..});
    // assert_eq!(next(sub1).await, LnReceiveState::Funded);

    Ok(())
}
