use std::sync::Arc;

use anyhow::Result;
use fedimint_api::task::TaskGroup;
use ln_gateway::{
    client::{GatewayClientBuilder, MemoryDbGatewayClientBuilder},
    config::GatewayConfig,
    rpc::GatewayRequest,
    LnGateway,
};
use tokio::sync::mpsc;

pub struct Fixtures {
    pub gateway: LnGateway,
    pub task_group: TaskGroup,
}

pub async fn fixtures(gw_cfg: GatewayConfig) -> Result<Fixtures> {
    let task_group = TaskGroup::new();

    let ln_rpc = Arc::new(MockLnRpc::new());

    let client_builder: GatewayClientBuilder = MemoryDbGatewayClientBuilder {}.into();
    let (tx, rx) = mpsc::channel::<GatewayRequest>(100);

    let gateway = LnGateway::new(gw_cfg, ln_rpc, client_builder, tx, rx, task_group.clone()).await;

    Ok(Fixtures {
        gateway,
        task_group,
    })
}
