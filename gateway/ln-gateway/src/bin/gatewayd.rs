use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use fedimint_core::config::ModuleGenRegistry;
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::DynModuleGen;
use fedimint_core::task::TaskGroup;
use fedimint_logging::TracingSetup;
use ln_gateway::client::{DynGatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder};
use ln_gateway::gatewayd::gateway::Gateway;
use ln_gateway::gatewayd::lnrpc_client::{DynLnRpcClient, NetworkLnRpcClient};
use mint_client::modules::ln::common::LightningDecoder;
use mint_client::modules::ln::LightningGen;
use mint_client::modules::mint::common::MintDecoder;
use mint_client::modules::mint::MintGen;
use mint_client::modules::wallet::common::WalletDecoder;
use mint_client::modules::wallet::WalletGen;
use tracing::{error, info};
use url::Url;

#[derive(Parser)]
pub struct GatewayOpts {
    /// Path to folder containing gateway config and data files
    #[arg(long = "data-dir", env = "FM_GATEWAY_DATA_DIR")]
    pub data_dir: PathBuf,

    /// Gateway webserver listen address
    #[arg(long = "listen", env = "FM_GATEWAY_LISTEN_ADDR")]
    pub listen: SocketAddr,

    /// Public URL from which the webserver API is reachable
    #[arg(long = "api-addr", env = "FM_GATEWAY_API_ADDR")]
    pub api_addr: Url,

    /// Gateway webserver authentication password
    #[arg(long = "password", env = "FM_GATEWAY_PASSWORD")]
    pub password: String,

    /// Public URL to a Gateway Lightning rpc service
    #[arg(long = "lnrpc-addr", env = "FM_GATEWAY_LIGHTNING_ADDR")]
    pub lnrpc_addr: Url,
}

// Fedimint Gateway Binary
///
/// This binary runs a webserver with an API that can be used by Fedimint
/// clients to request routing of payments through the Lightning Network.
/// It uses a `GatewayLightningClient`, an rpc client to communicate with a
/// remote Lightning node accessible through a `GatewayLightningServer`.
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    TracingSetup::default().init()?;
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("CODE_VERSION"));
            return Ok(());
        }
    }

    // Read configurations
    let GatewayOpts {
        data_dir,
        listen,
        api_addr,
        lnrpc_addr,
        password,
    } = GatewayOpts::parse();

    info!(
        "Starting gateway with these configs \n data directory: {:?},\n listen: {},\n api address: {},\n lnrpc address: {} ",
        data_dir, listen, api_addr, lnrpc_addr
    );

    // Create federation client builder
    let client_builder: DynGatewayClientBuilder =
        StandardGatewayClientBuilder::new(data_dir.clone(), RocksDbFactory.into(), api_addr).into();

    // Create task group for controlled shutdown of the gateway
    let task_group = TaskGroup::new();

    // Create a lightning rpc client
    let lnrpc: DynLnRpcClient = NetworkLnRpcClient::new(lnrpc_addr).await?.into();

    // Create module decoder registry
    let decoders = ModuleDecoderRegistry::from_iter([
        (LEGACY_HARDCODED_INSTANCE_ID_LN, LightningDecoder.into()),
        (LEGACY_HARDCODED_INSTANCE_ID_MINT, MintDecoder.into()),
        (LEGACY_HARDCODED_INSTANCE_ID_WALLET, WalletDecoder.into()),
    ]);

    // Create module generator registry
    let module_gens = ModuleGenRegistry::from(vec![
        DynModuleGen::from(WalletGen),
        DynModuleGen::from(MintGen),
        DynModuleGen::from(LightningGen),
    ]);

    // Create gateway instance
    let gateway = Gateway::new(
        lnrpc,
        client_builder,
        decoders,
        module_gens,
        task_group.clone(),
    )
    .await;

    if let Err(e) = gateway.run(listen, password).await {
        task_group.shutdown_join_all(None).await?;

        error!("Gateway stopped with error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
