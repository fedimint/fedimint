use cln_plugin::Error;
use fedimint_api::task::TaskGroup;
use ln_gateway::{
    client::{GatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder},
    cln::{build_cln_rpc, ClnRpcRef},
    rpc::{GatewayRequest, GatewayRpcSender},
    utils::read_gateway_config,
    LnGateway,
};
use tokio::sync::mpsc;
use tracing::error;

/// Fedimint gateway packaged as a CLN plugin
#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }

    // Create message channels
    let (tx, rx) = mpsc::channel::<GatewayRequest>(100);

    let ClnRpcRef { ln_rpc, work_dir } = build_cln_rpc(GatewayRpcSender::new(tx.clone())).await?;

    let gw_cfg = read_gateway_config(Some(work_dir.clone()))?;

    // Create federation client builder
    let client_builder: GatewayClientBuilder =
        StandardGatewayClientBuilder::new(work_dir.clone(), RocksDbFactory.into()).into();

    // Create gateway instance
    let task_group = TaskGroup::new();
    let gateway = LnGateway::new(gw_cfg, ln_rpc, client_builder, tx, rx, task_group.clone()).await;

    if let Err(e) = gateway.run().await {
        task_group.shutdown_join_all().await?;

        error!("Gateway stopped with error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
