use clap::Parser;
use fedimint::setup::run_setup;
use std::path::PathBuf;

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
    let Options { dir_out_path, port } = Options::parse();
    run_setup(dir_out_path, port).await;
}
