use std::str::FromStr;

use assert_matches::assert_matches;
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client::Client;
use fedimint_core::sats;
use fedimint_core::util::NextOrPending;
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::{LightningClientExt, LightningClientGen, LnPayState};
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::{Fixtures, GatewayFixtures};
use fedimint_testing::ln::LightningNodeType;
use lightning::routing::gossip::RoutingFees;
use ln_gateway::ng::{GatewayClientExt, GatewayClientGen, GatewayExtPayStates};
use url::Url;

async fn fixtures(gateway_node: &LightningNodeType) -> (Fixtures, GatewayFixtures) {
    let fixtures = Fixtures::new_primary(1, DummyClientGen, DummyGen, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_rpc());
    let fixtures = fixtures.with_module(0, LightningClientGen, LightningGen, ln_params);
    let gateway_fixtures = GatewayFixtures::new(gateway_node).await;
    (fixtures, gateway_fixtures)
}

async fn new_gateway_client(
    fed: &FederationTest,
    gateway_fixtures: &GatewayFixtures,
) -> anyhow::Result<Client> {
    let mut registry = ClientModuleGenRegistry::new();
    registry.attach(DummyClientGen);
    registry.attach(GatewayClientGen {
        lightning_client: gateway_fixtures.gateway_lightning_client.clone(),
        fees: RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        },
        timelock_delta: 10,
        mint_channel_id: 1,
    });
    let gateway = fed.new_gateway_client(registry).await;
    let fake_api = Url::from_str("http://127.0.0.1:8175").unwrap();
    gateway.register_with_federation(fake_api).await?;
    Ok(gateway)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_valid_invoice() -> anyhow::Result<()> {
    let gateway_node = LightningNodeType::Lnd;

    let (fixtures, gateway_fixtures) = fixtures(&gateway_node).await;
    let fed = fixtures.new_fed().await;
    let user_client = fed.new_client().await;

    let gateway = new_gateway_client(&fed, &gateway_fixtures).await?;

    // Print money for user_client
    let (_, outpoint) = user_client.print_money(sats(1000)).await?;
    user_client.receive_money(outpoint).await?;
    assert_eq!(user_client.get_balance().await, sats(1000));

    // Create test invoice
    let invoice = gateway_fixtures
        .other_lightning_client
        .invoice(sats(250), None)
        .await?;

    // User client pays test invoice
    let (pay_op, contract_id) = user_client.pay_bolt11_invoice(invoice.clone()).await?;
    let mut pay_sub = user_client.subscribe_ln_pay(pay_op).await?.into_stream();
    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
    let funded = pay_sub.ok().await?;
    assert_matches!(funded, LnPayState::Funded);

    let gw_pay_op = gateway.gateway_pay_bolt11_invoice(contract_id).await?;
    let mut gw_pay_sub = gateway
        .gateway_subscribe_ln_pay(gw_pay_op)
        .await?
        .into_stream();
    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Preimage);
    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Success);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_client_pay_invalid_invoice() -> anyhow::Result<()> {
    let gateway_node = LightningNodeType::Lnd;

    let (fixtures, gateway_fixtures) = fixtures(&gateway_node).await;
    let fed = fixtures.new_fed().await;
    let user_client = fed.new_client().await;

    let gateway = new_gateway_client(&fed, &gateway_fixtures).await?;

    // Print money for client2
    let (_, outpoint) = user_client.print_money(sats(1000)).await?;
    user_client.receive_money(outpoint).await?;
    assert_eq!(user_client.get_balance().await, sats(1000));

    // Create test invoice
    let invoice = gateway_fixtures
        .other_lightning_client
        .invalid_invoice(sats(250), None)
        .unwrap();

    // User client pays test invoice
    let (pay_op, contract_id) = user_client.pay_bolt11_invoice(invoice.clone()).await?;
    let mut pay_sub = user_client.subscribe_ln_pay(pay_op).await?.into_stream();
    assert_eq!(pay_sub.ok().await?, LnPayState::Created);
    let funded = pay_sub.ok().await?;
    assert_matches!(funded, LnPayState::Funded);

    let gw_pay_op = gateway.gateway_pay_bolt11_invoice(contract_id).await?;
    let mut gw_pay_sub = gateway
        .gateway_subscribe_ln_pay(gw_pay_op)
        .await?
        .into_stream();
    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Created);
    assert_eq!(gw_pay_sub.ok().await?, GatewayExtPayStates::Canceled);

    Ok(())
}
