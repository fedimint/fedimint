use fedimint_logging::TracingSetup;
use ln_gateway::Gateway;
use tracing::info;

/// Fedimint Gateway Binary
///
/// This binary runs a webserver with an API that can be used by Fedimint
/// clients to request routing of payments through the Lightning Network.
/// It uses a `GatewayLightningClient`, an rpc client to communicate with a
/// remote Lightning node accessible through a `GatewayLightningServer`.
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    TracingSetup::default().init()?;
    let shutdown_receiver = Gateway::new_with_default_modules().await?.run().await?;
    shutdown_receiver.await;
    info!("Gatewayd exiting...");
    Ok(())
}
