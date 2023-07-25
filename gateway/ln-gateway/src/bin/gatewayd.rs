use ln_gateway::Gatewayd;

/// Fedimint Gateway Binary
///
/// This binary runs a webserver with an API that can be used by Fedimint
/// clients to request routing of payments through the Lightning Network.
/// It uses a `GatewayLightningClient`, an rpc client to communicate with a
/// remote Lightning node accessible through a `GatewayLightningServer`.
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    Gatewayd::new()?.with_default_modules().run().await
}
