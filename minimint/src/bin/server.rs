use config::{load_from_file, ServerConfig, ServerOpts};
use minimint::consensus::FediMint;
use structopt::StructOpt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let opts: ServerOpts = StructOpt::from_args();
    let cfg: ServerConfig = load_from_file(&opts.cfg_path);

    let mut fedi_mint = FediMint::init(rand::rngs::OsRng::new().unwrap(), cfg).await;
    fedi_mint.run().await;
}
