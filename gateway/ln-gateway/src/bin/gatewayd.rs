use fedimint_api::task::TaskGroup;
use ln_gateway::{
    client::{GatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder},
    utils::{read_gateway_config, try_read_gateway_dir},
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
    let config = read_gateway_config(Some(dir.clone()))?;

    // Create federation client builder
    let client_builder: GatewayClientBuilder =
        StandardGatewayClientBuilder::new(dir.clone(), RocksDbFactory.into()).into();

    // Create gateway instance
    let task_group = TaskGroup::new();
    let gateway = LnGateway::new(config, client_builder, task_group.clone()).await;

    if let Err(e) = gateway.run().await {
        task_group.shutdown_join_all().await?;

        error!("Gateway stopped with error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
