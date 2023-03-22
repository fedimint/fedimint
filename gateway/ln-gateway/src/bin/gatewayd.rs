use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::exit;

use clap::{Parser, Subcommand};
use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen};
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::ModuleCommon;
use fedimint_core::task::TaskGroup;
use fedimint_logging::TracingSetup;
use ln_gateway::client::{DynGatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder};
use ln_gateway::lnd::GatewayLndClient;
use ln_gateway::lnrpc_client::{DynLnRpcClient, NetworkLnRpcClient};
use ln_gateway::Gateway;
use mint_client::modules::ln::{LightningClientGen, LightningModuleTypes};
use mint_client::modules::mint::{MintClientGen, MintModuleTypes};
use mint_client::modules::wallet::{WalletClientGen, WalletModuleTypes};
use tracing::{error, info};
use url::Url;

#[derive(Parser)]
pub struct GatewayOpts {
    #[clap(subcommand)]
    mode: Mode,

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
}

#[derive(Debug, Clone, Subcommand)]
enum Mode {
    #[clap(name = "lnd")]
    Lnd {
        /// LND RPC address
        #[arg(long = "lnd-rpc-host", env = "FM_LND_RPC_ADDR")]
        lnd_rpc_addr: String,

        /// LND TLS cert file path
        #[arg(long = "lnd-tls-cert", env = "FM_LND_TLS_CERT")]
        lnd_tls_cert: String,

        /// LND macaroon file path
        #[arg(long = "lnd-macaroon", env = "FM_LND_MACAROON")]
        lnd_macaroon: String,
    },
    #[clap(name = "cln")]
    Cln {
        #[arg(long = "cln-extension-addr", env = "FM_GATEWAY_LIGHTNING_ADDR")]
        cln_extension_addr: Url,
    },
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
        mode,
        data_dir,
        listen,
        api_addr,
        password,
    } = GatewayOpts::parse();

    info!(
        "Starting gateway with these base configs \n data directory: {:?},\n listen: {},\n api address: {} ",
        data_dir, listen, api_addr
    );

    // Create federation client builder
    let client_builder: DynGatewayClientBuilder =
        StandardGatewayClientBuilder::new(data_dir.clone(), RocksDbFactory.into(), api_addr).into();

    // Create task group for controlled shutdown of the gateway
    let task_group = TaskGroup::new();

    let lnrpc: DynLnRpcClient = match mode {
        Mode::Cln { cln_extension_addr } => {
            info!(
                "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {:?} ",
                cln_extension_addr
            );
            NetworkLnRpcClient::new(cln_extension_addr).await?.into()
        }
        Mode::Lnd {
            lnd_rpc_addr,
            lnd_tls_cert,
            lnd_macaroon,
        } => {
            info!(
                "Gateway configured to connect to LND LnRpcClient at \n address: {:?},\n tls cert path: {:?},\n macaroon path: {} ",
                lnd_rpc_addr, lnd_tls_cert, lnd_macaroon
            );
            GatewayLndClient::new(
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
                task_group.make_subgroup().await,
            )
            .await?
            .into()
        }
    };

    // Create module decoder registry
    let decoders = ModuleDecoderRegistry::from_iter([
        (
            LEGACY_HARDCODED_INSTANCE_ID_LN,
            LightningModuleTypes::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            MintModuleTypes::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            WalletModuleTypes::decoder(),
        ),
    ]);

    // Create module generator registry
    let module_gens = ClientModuleGenRegistry::from(vec![
        DynClientModuleGen::from(WalletClientGen),
        DynClientModuleGen::from(MintClientGen),
        DynClientModuleGen::from(LightningClientGen),
    ]);

    // Create gateway instance
    let gateway = Gateway::new(
        lnrpc,
        client_builder,
        decoders,
        module_gens,
        task_group.make_subgroup().await,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("Failed to start gateway: {e:?}");
        exit(1)
    });

    if let Err(e) = gateway.run(listen, password).await {
        task_group.shutdown_join_all(None).await?;

        error!("Gateway stopped with error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
