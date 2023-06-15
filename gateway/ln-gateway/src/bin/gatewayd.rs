use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::exit;

use clap::Parser;
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{CommonModuleGen, ModuleCommon};
use fedimint_ln_client::LightningCommonGen;
use fedimint_ln_common::config::GatewayFee;
use fedimint_ln_common::LightningModuleTypes;
use fedimint_logging::TracingSetup;
use fedimint_mint_client::{MintCommonGen, MintModuleTypes};
use fedimint_wallet_client::{WalletCommonGen, WalletModuleTypes};
use ln_gateway::client::StandardGatewayClientBuilder;
use ln_gateway::{Gateway, GatewayError, LightningMode, DEFAULT_FEES};
use tracing::info;
use url::Url;

const DB_FILE: &str = "gatewayd.db";

#[derive(Parser)]
pub struct GatewayOpts {
    #[clap(subcommand)]
    mode: LightningMode,

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

    /// Configured gateway routing fees
    /// Format: <base_msat>,<proportional_millionths>
    #[arg(long = "fees", env = "FM_GATEWAY_FEES")]
    pub fees: Option<GatewayFee>,
}

/// Fedimint Gateway Binary
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
        fees,
    } = GatewayOpts::parse();

    info!(
        "Starting gateway with these base configs \n data directory: {:?},\n listen: {},\n api address: {} ",
        data_dir, listen, api_addr
    );

    // Create federation client builder
    let client_builder = StandardGatewayClientBuilder::new(data_dir.clone());

    // Create module decoder registry
    let decoders = ModuleDecoderRegistry::from_iter([
        (
            LEGACY_HARDCODED_INSTANCE_ID_LN,
            LightningCommonGen::KIND,
            LightningModuleTypes::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            MintCommonGen::KIND,
            MintModuleTypes::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            WalletCommonGen::KIND,
            WalletModuleTypes::decoder(),
        ),
    ]);

    let gatewayd_db = Database::new(
        fedimint_rocksdb::RocksDb::open(data_dir.join(DB_FILE))
            .map_err(|_| GatewayError::DatabaseError)?,
        decoders.clone(),
    );

    // Create gateway instance
    let gateway = Gateway::new(
        mode,
        client_builder,
        fees.unwrap_or(GatewayFee(DEFAULT_FEES)).0,
        gatewayd_db,
        api_addr,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("Failed to start gateway: {e:?}");
        exit(1)
    });

    gateway.spawn_blocking_webserver(listen, password).await;

    Ok(())
}
