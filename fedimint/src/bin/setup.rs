use clap::Parser;
use fedimint::config::ServerConfig;
use fedimint::run_fedimint;
use fedimint::setup::run_setup;
use fedimint_core::config::load_from_file;
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Parser)]
struct Options {
    /// Directory to output all the generated config files
    #[clap(long = "out-dir")]
    dir_out_path: PathBuf,

    /// Setup webserver port
    #[clap(long = "port")]
    port: u16,
}

#[tokio::main]
async fn main() {
    let (sender, mut receiver) = mpsc::channel(32);
    let Options { dir_out_path, port } = Options::parse();
    let dir_out_path_clone = dir_out_path.clone();
    tokio::task::spawn(run_setup(dir_out_path_clone, port, sender));

    // TODO: check if config exists already. if so, just run now.

    if let Some((cfg_path, db_path)) = receiver.recv().await {
        let cfg: ServerConfig = load_from_file(&cfg_path);
        tracing::info!("Running fedimint");
        run_fedimint(cfg.clone(), db_path.clone()).await;
    }
}
