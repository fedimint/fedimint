use std::sync::Arc;

use fedimint_dummy_client::DummyClientGen;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::LightningClientGen;
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::{GatewayTest, DEFAULT_GATEWAY_PASSWORD};
use ln_gateway::rpc::rpc_client::GatewayRpcClient;

/// Constructs a gateway connected to 2 federations for RPC tests
pub async fn fixtures() -> (
    GatewayTest,
    GatewayRpcClient,
    FederationTest,
    FederationTest,
    Arc<dyn BitcoinTest>,
) {
    let mut fixtures = Fixtures::new_primary(DummyClientGen, DummyGen, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_server());
    fixtures = fixtures.with_module(LightningClientGen, LightningGen, ln_params);

    let lnd = fixtures.lnd().await;
    let gateway = fixtures
        .new_gateway(lnd, 0, Some(DEFAULT_GATEWAY_PASSWORD.to_string()))
        .await;
    let client = gateway
        .get_rpc()
        .await
        .with_password(Some(DEFAULT_GATEWAY_PASSWORD.to_string()));

    let fed1 = fixtures.new_fed().await;
    let fed2 = fixtures.new_fed().await;

    (gateway, client, fed1, fed2, fixtures.bitcoin())
}
