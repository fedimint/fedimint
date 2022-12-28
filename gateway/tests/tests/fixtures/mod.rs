use anyhow::Result;
use fedimint_api::task::TaskGroup;
use fedimint_testing::{
    btc::{fixtures::FakeBitcoinTest, BitcoinTest},
    ln::fixtures::FakeLnRpcClientFactory,
};
use ln_gateway::{
    client::{GatewayClientBuilder, MemDbFactory},
    config::GatewayConfig,
    rpc::lnrpc_client::LnRpcClientFactory,
    LnGateway,
};

pub mod client;
pub mod fed;

pub struct Fixtures {
    pub bitcoin: Box<dyn BitcoinTest>,
    pub gateway: LnGateway,
    pub task_group: TaskGroup,
}

pub async fn fixtures(gw_cfg: GatewayConfig) -> Result<Fixtures> {
    let task_group = TaskGroup::new();

    let client_builder: GatewayClientBuilder =
        client::TestGatewayClientBuilder::new(MemDbFactory.into()).into();

    let lnrpc_factory: LnRpcClientFactory = FakeLnRpcClientFactory::default().into();

    let gateway = LnGateway::new(gw_cfg, lnrpc_factory, client_builder, task_group.clone()).await;
    let bitcoin = Box::new(FakeBitcoinTest::new());

    Ok(Fixtures {
        bitcoin,
        gateway,
        task_group,
    })
}
