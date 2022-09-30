use std::path::PathBuf;

use clap::Parser;
use fedimint_server::config::{load_from_file, ServerConfig};
use fedimint_server::FedimintServer;
use fedimint_wallet::bitcoincore_rpc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

#[derive(Parser)]
pub struct ServerOpts {
    pub cfg_path: PathBuf,
    pub db_path: PathBuf,
    #[cfg(feature = "telemetry")]
    #[clap(long)]
    pub with_telemetry: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();
    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }
    let opts = ServerOpts::parse();
    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer);

    let telemetry_layer = || -> Option<Box<dyn Layer<_> + Send + Sync + 'static>> {
        #[cfg(feature = "telemetry")]
        if opts.with_telemetry {
            let tracer = opentelemetry_jaeger::new_pipeline()
                .with_service_name("fedimint")
                .install_simple()
                .unwrap();

            return Some(tracing_opentelemetry::layer().with_tracer(tracer).boxed());
        }
        None
    };

    if let Some(layer) = telemetry_layer() {
        registry.with(layer).init();
    } else {
        registry.init();
    }

    let cfg: ServerConfig = load_from_file(&opts.cfg_path);

    let db = fedimint_rocksdb::RocksDb::open(opts.db_path)
        .expect("Error opening DB")
        .into();

    let btc_rpc = bitcoincore_rpc::make_bitcoind_rpc(&cfg.wallet.btc_rpc)?;
    FedimintServer::run(cfg, db, btc_rpc).await;

    #[cfg(feature = "telemetry")]
    opentelemetry::global::shutdown_tracer_provider();

    Ok(())
}
