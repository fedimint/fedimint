use config::{load_from_file, ServerConfig, ServerOpts};
use minimint::run_minimint;
use structopt::StructOpt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tide=error")),
        )
        .init();

    let opts: ServerOpts = StructOpt::from_args();
    let cfg: ServerConfig = load_from_file(&opts.cfg_path);
    let rng = rand::rngs::OsRng::new().expect("Could not initialize RNG");

    run_minimint(rng, cfg).await;
}
