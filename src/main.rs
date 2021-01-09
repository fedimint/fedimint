#![feature(async_closure)]

use structopt::StructOpt;
use tracing::Level;
use tracing::{debug, error, info};

mod config;
mod connect;
mod keygen;
mod peer;

#[tokio::main]
async fn main() {
    let cfg: config::Config = StructOpt::from_args();
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let connections = connect::connect_to_all(&cfg).await;
    let (peers, pub_key_set, sec_key, sec_key_share) =
        keygen::generate_keys(&cfg, connections).await;

    info!("Exiting");
}
