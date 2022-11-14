use cln_plugin::Error;
use fedimint_server::config::load_from_file;
use ln_gateway::{
    client::{GatewayClientBuilder, RocksDbGatewayClientBuilder},
    cln::build_cln_rpc,
    config::GatewayConfig,
    ln::LnRpcRef,
    rpc::{GatewayRequest, GatewayRpcSender},
    LnGateway,
};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }
    let (tx, rx): (mpsc::Sender<GatewayRequest>, mpsc::Receiver<GatewayRequest>) =
        mpsc::channel(100);

    let sender = GatewayRpcSender::new(tx.clone());
    let LnRpcRef {
        ln_rpc,
        bind_addr,
        pub_key,
        work_dir,
    } = build_cln_rpc(sender).await?;

    let gw_cfg_path = work_dir.clone().join("gateway.config");
    let gw_cfg: GatewayConfig = load_from_file(&gw_cfg_path);

    // Create federation client builder
    let client_builder: GatewayClientBuilder =
        RocksDbGatewayClientBuilder::new(work_dir.clone()).into();

    // Create gateway instance
    let mut gateway = LnGateway::new(gw_cfg, ln_rpc, client_builder, tx, rx, bind_addr, pub_key);

    // Start gateway
    gateway.run().await.expect("gateway failed to run");

    Ok(())
}
