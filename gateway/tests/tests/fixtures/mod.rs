use std::sync::Arc;

use anyhow::Result;
use fedimint_api::task::TaskGroup;
use fedimint_testing::btc::{fixtures::FakeBitcoinTest, BitcoinTest};
use ln_gateway::{
    client::{GatewayClientBuilder, MemDbFactory},
    config::GatewayConfig,
    rpc::GatewayRequest,
    LnGateway,
};
use tokio::sync::mpsc;

pub mod client;
pub mod fed;
pub mod ln;

pub struct Fixtures {
    pub bitcoin: Box<dyn BitcoinTest>,
    pub gateway: LnGateway,
    pub task_group: TaskGroup,
}

pub async fn fixtures(gw_cfg: GatewayConfig) -> Result<Fixtures> {
    let task_group = TaskGroup::new();

    let ln_rpc = Arc::new(ln::MockLnRpc::new());

    let client_builder: GatewayClientBuilder =
        client::TestGatewayClientBuilder::new(MemDbFactory.into()).into();
    let (tx, rx) = mpsc::channel::<GatewayRequest>(100);

    let gateway = LnGateway::new(gw_cfg, ln_rpc, client_builder, tx, rx, task_group.clone()).await;
    let bitcoin = Box::new(FakeBitcoinTest::new());

    Ok(Fixtures {
        bitcoin,
        gateway,
        task_group,
    })
}
