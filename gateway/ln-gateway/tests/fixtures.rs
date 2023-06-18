use fedimint_dummy_client::DummyClientGen;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_ln_client::LightningClientGen;
use fedimint_ln_common::config::LightningGenParams;
use fedimint_ln_server::LightningGen;
use fedimint_testing::btc::mock::FakeBitcoinTest;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing::gateway::GatewayTest;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;

pub async fn fixtures(
    password: Option<String>,
) -> (
    GatewayTest,
    GatewayRpcClient,
    FederationTest,
    FederationTest,
    Box<dyn BitcoinTest>,
) {
    // TODO: use new client modules without legacy instances
    let mut fixtures =
        Fixtures::new_primary(1, DummyClientGen, DummyGen, DummyGenParams::default());
    let ln_params = LightningGenParams::regtest(fixtures.bitcoin_server());
    fixtures = fixtures.with_module(0, LightningClientGen, LightningGen, ln_params);

    let gateway = fixtures.new_gateway(password).await;
    let client = gateway.get_rpc().await;

    let fed1 = fixtures.new_fed().await;
    let fed2 = fixtures.new_fed().await;

    // TODO: Source this from the Fixtures, based on test environment
    let bitcoin = Box::new(FakeBitcoinTest::new());

    (gateway, client, fed1, fed2, bitcoin)
}
