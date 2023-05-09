//! Gateway integration test suite
//!
//! This crate contains integration tests for the gateway business logic.
//!
//! The tests run instances of gatewayd with the following mocks:
//!
//! * `ILnRpcClient` - fake implementation of `ILnRpcClient` that simulates
//!   gateway lightning dependency.
//!
//! * `IFederationApi` - fake implementation of `IFederationApi` that simulates
//!   gateway federation client dependency.

use fedimint_dummy_client::DummyClientGen;
use fedimint_dummy_common::config::DummyConfigGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::LightningClientGen;
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::GatewayTest;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;

async fn fixtures() -> (
    FederationTest,
    FederationTest,
    GatewayTest,
    GatewayRpcClient,
) {
    // TODO: use new client modules without legacy instances
    let fixtures = Fixtures::default()
        .with_primary(1, DummyClientGen, DummyGen, DummyConfigGenParams::default())
        .with_module(0, LightningClientGen, LightningGen, LightningGenParams);

    let fed1 = fixtures.new_fed(1).await;
    let fed2 = fixtures.new_fed(1).await;
    let gateway = fixtures.new_gateway().await;
    gateway.connect_fed(&fed1).await;
    gateway.connect_fed(&fed2).await;
    let client = gateway.new_client().await;
    (fed1, fed2, gateway, client)
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_supports_multiple_federations() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_shows_info_about_all_connected_federations() {
    let (_, _, _, client) = fixtures().await;
    let info = client.get_info().await.unwrap();
    assert_eq!(info.federations.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_shows_balance_for_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_allows_deposit_to_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_allows_withdrawal_from_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_supports_backup_of_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_supports_restore_of_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

// Internal payments within a federation should not involve the gateway. See
// Issue #613: Federation facilitates internal payments w/o involving gateway
#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_pays_internal_invoice_within_a_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_pays_outgoing_invoice_to_generic_ln() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_pays_outgoing_invoice_between_federations_connected() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_intercepts_htlc_and_settles_to_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}
