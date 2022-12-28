use fedimint_api::task::TaskGroup;
use fedimint_server::config::load_from_file;
use ln_gateway::{
    client::{GatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder},
    config::GatewayConfig,
    rpc::lnrpc_client::{LnRpcClientFactory, NetworkLnRpcClientFactory},
    utils::try_read_gateway_dir,
    LnGateway,
};
use tracing::error;

/**
 * Fedimint Gateway Binary
 *
 * This binary runs a webserver with an API that can be used by Fedimint clients to request routing of payments
 * through the Lightning Network. It uses a Gateway Lightning RPC client to communicate with a Lightning node.
 */
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }

    // Read configurations
    let dir = try_read_gateway_dir()?;
    let gw_cfg_path = dir.join("gateway.config");
    let config: GatewayConfig = load_from_file(&gw_cfg_path).expect("Failed to parse config");

    // Create federation client builder
    let client_builder: GatewayClientBuilder =
        StandardGatewayClientBuilder::new(dir.clone(), RocksDbFactory.into()).into();

    // Create task group for controlled shutdown of the gateway
    let task_group = TaskGroup::new();

    // Create a lightning rpc client factory
    let lnrpc_factory: LnRpcClientFactory = NetworkLnRpcClientFactory::default().into();

    // Create gateway instance
    let gateway = LnGateway::new(config, lnrpc_factory, client_builder, task_group.clone()).await;

    if let Err(e) = gateway.run().await {
        task_group.shutdown_join_all().await?;

        error!("Gateway stopped with error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
