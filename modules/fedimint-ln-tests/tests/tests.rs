use assert_matches::assert_matches;
use fedimint_client::Client;
use fedimint_core::sats;
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{LightningClientExt, LightningClientGen, LnPayState, LnReceiveState};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_mint_client::{MintClientExt, MintClientGen};
use fedimint_mint_common::config::MintGenParams;
use fedimint_mint_server::MintGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::{next, Fixtures};
use fedimint_testing::gateway::GatewayTest;
use fedimint_wallet_client::WalletClientGen;
use fedimint_wallet_common::config::WalletGenParams;
use fedimint_wallet_tests::FakeWalletGen;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new();
    let wallet_gen = FakeWalletGen::new(&fixtures);
    fixtures
        .with_module(3, DummyClientGen, DummyGen, DummyGenParams::default())
        .with_module(
            0,
            LightningClientGen,
            LightningGen,
            LightningGenParams::default(),
        )
        // TODO: Remove dependency on mint (legacy gw client)
        .with_primary(1, MintClientGen, MintGen, MintGenParams::default())
        // TODO: Remove dependency on wallet interconnect
        .with_module(2, WalletClientGen, wallet_gen, WalletGenParams::default())
}

/// Setup a gateway connected to the fed and client
async fn gateway(fixtures: &Fixtures, fed: &FederationTest, client: &Client) -> GatewayTest {
    let gateway = fixtures.new_gateway(fed).await;
    let node_pub_key = gateway.last_info().registration.node_pub_key;
    client.set_active_gateway(&node_pub_key).await.unwrap();
    gateway
}

#[tokio::test(flavor = "multi_thread")]
async fn can_switch_active_gateway() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;

    // Client selects a gateway by default
    let gateway1 = fixtures.new_gateway(&fed).await.last_info().registration;
    assert_eq!(client.select_active_gateway().await?, gateway1);

    let gateway2 = fixtures.new_gateway(&fed).await.last_info().registration;
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
    let gateway = gateway(&fixtures, &fed, &client1).await;
    let fed_id = gateway.last_info().federation_id;

    // Print money for client2
    let (op, outpoint) = client2.print_money(sats(1000)).await.unwrap();
    client2.await_claim_notes(op, outpoint.txid).await?;

    let (op, invoice) = client1
        .create_bolt11_invoice(sats(250), "description".to_string(), None)
        .await?;
    let sub1 = &mut client1.subscribe_to_ln_receive_updates(op).await.unwrap();
    assert_eq!(next(sub1).await, LnReceiveState::Created);
    assert_matches!(next(sub1).await, LnReceiveState::WaitingForPayment { .. });

    let (op, _txid) = client2.pay_bolt11_invoice(fed_id, invoice).await.unwrap();
    let sub2 = &mut client2.subscribe_ln_pay_updates(op).await.unwrap();
    assert_eq!(next(sub2).await, LnPayState::Created);
    // TODO: Finish after gw moves from legacy client
    // assert_eq!(next(sub2).await, LnPayState::Funded);
    // assert_matches!(next(sub2).await, LnPayState::Success{..});
    // assert_eq!(next(sub1).await, LnReceiveState::Funded);

    Ok(())
}
