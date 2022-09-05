use clap::Parser;
use fedimint::config::ServerConfig;
use fedimint::run_fedimint;
use fedimint::setup::run_setup;
use fedimint_core::config::load_from_file;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

#[derive(Parser)]
struct Options {
    /// Directory to output all the generated config files
    #[clap(long = "out-dir")]
    dir_out_path: PathBuf,

    /// Setup webserver port
    #[clap(long = "port")]
    port: u16,
}

// TODO: make a shell script to ensure that bitcoind / lightningd are running ...
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let (sender, mut receiver) = mpsc::channel(32);
    let Options { dir_out_path, port } = Options::parse();
    let dir_out_path_clone = dir_out_path.clone();
    // tokio::task::spawn(run_setup(dir_out_path_clone, port, sender));
    //
    // let cfg_path = dir_out_path.join(format!("server-{}.json", port));
    // let db_path = dir_out_path.join(format!("server-{}.db", port));
    // if Path::new(&cfg_path).is_file() {
    //     let cfg: ServerConfig = load_from_file(&cfg_path);
    //     tracing::info!("Running fedimint");
    //     run_fedimint(cfg.clone(), db_path.clone()).await;
    // }
    //
    // if let Some(_) = receiver.recv().await {
    //     let cfg: ServerConfig = load_from_file(&cfg_path);
    //     tracing::info!("Running fedimint");
    //     run_fedimint(cfg.clone(), db_path.clone()).await;
    // }
}
