use cln_plugin::Error;
use fedimint_server::config::load_from_file;
use ln_gateway::{
    client::{GatewayClientBuilder, RocksDbGatewayClientBuilder},
    cln::{build_cln_rpc, ClnRpcRef},
    config::GatewayConfig,
    rpc::{GatewayRequest, GatewayRpcSender},
    LnGateway,
};
use tokio::sync::mpsc;

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

    let gw_cfg_path = work_dir.clone().join("gateway.config");
    let gw_cfg: GatewayConfig = load_from_file(&gw_cfg_path);

    // Create federation client builder
    let client_builder: GatewayClientBuilder =
        RocksDbGatewayClientBuilder::new(work_dir.clone()).into();

    // Create gateway instance
    let mut gateway = LnGateway::new(gw_cfg, ln_rpc, client_builder, tx, rx);

    // Start gateway
    gateway.run().await.expect("gateway failed to run");

    Ok(())
}
