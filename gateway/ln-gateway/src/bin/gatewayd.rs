use std::path::PathBuf;

use clap::Parser;
use fedimint_api::{
    core::{
        LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
        LEGACY_HARDCODED_INSTANCE_ID_WALLET,
    },
    module::registry::ModuleDecoderRegistry,
    task::TaskGroup,
};
use fedimint_server::{
    config::load_from_file,
    modules::{
        ln::common::LightningDecoder, mint::common::MintDecoder, wallet::common::WalletDecoder,
    },
};
use ln_gateway::{
    client::{DynGatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder},
    config::GatewayConfig,
    gateway::Gateway,
    rpc::lnrpc_client::{DynLnRpcClientFactory, NetworkLnRpcClientFactory},
};
use tracing::{error, info};

#[derive(Parser)]
pub struct GatewayOpts {
    /// Path to folder containing gateway config and data files
    #[arg(long = "cfg-dir", env = "GW_CONFIG_DIR")]
    pub cfg_dir: PathBuf,
}

/// Fedimint Gateway Binary
///
/// This binary runs a webserver with an API that can be used by Fedimint clients to request routing of payments
/// through the Lightning Network. It uses a Gateway Lightning RPC client to communicate with a Lightning node.
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
    let GatewayOpts { cfg_dir } = GatewayOpts::parse();
    let gw_cfg_path = cfg_dir.join("gateway.config");
    let config: GatewayConfig = match load_from_file(&gw_cfg_path) {
        Ok(cfg) => {
            info!("Loaded gateway config from {}", gw_cfg_path.display());
            cfg
        }
        Err(e) => {
            error!("Failed to load gateway config: {}", e);
            return Err(e);
        }
    };

    // Create federation client builder
    let client_builder: DynGatewayClientBuilder =
        StandardGatewayClientBuilder::new(cfg_dir.clone(), RocksDbFactory.into()).into();

    // Create task group for controlled shutdown of the gateway
    let task_group = TaskGroup::new();

    // Create a lightning rpc client factory
    let lnrpc_factory: DynLnRpcClientFactory = NetworkLnRpcClientFactory::default().into();

    // Create module decoder registry
    let decoders = ModuleDecoderRegistry::from_iter([
        (LEGACY_HARDCODED_INSTANCE_ID_LN, LightningDecoder.into()),
        (LEGACY_HARDCODED_INSTANCE_ID_MINT, MintDecoder.into()),
        (LEGACY_HARDCODED_INSTANCE_ID_WALLET, WalletDecoder.into()),
    ]);

    // Create gateway instance
    let gateway = Gateway::new(
        config,
        decoders,
        lnrpc_factory,
        client_builder,
        task_group.clone(),
    )
    .await;

    if let Err(e) = gateway.run().await {
        task_group.shutdown_join_all().await?;

        error!("Gateway stopped with error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
