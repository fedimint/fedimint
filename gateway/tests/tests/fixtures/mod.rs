use std::sync::Arc;

use anyhow::Result;
use fedimint_api::task::TaskGroup;
use fedimint_testing::btc::fixtures::FakeBitcoinTest;
use fedimint_testing::btc::BitcoinTest;
use ln_gateway::client::{DynGatewayClientBuilder, MemDbFactory};
use ln_gateway::config::GatewayConfig;
use ln_gateway::rpc::GatewayRequest;
use ln_gateway::LnGateway;
use mint_client::module_decode_stubs;
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

    let client_builder: DynGatewayClientBuilder =
        client::TestGatewayClientBuilder::new(MemDbFactory.into()).into();
    let (tx, rx) = mpsc::channel::<GatewayRequest>(100);
    let decoders = module_decode_stubs();

    let gateway = LnGateway::new(
        gw_cfg,
        decoders,
        ln_rpc,
        client_builder,
        tx,
        rx,
        task_group.clone(),
    )
    .await;
    let bitcoin = Box::new(FakeBitcoinTest::new());

    Ok(Fixtures {
        bitcoin,
        gateway,
        task_group,
    })
}
