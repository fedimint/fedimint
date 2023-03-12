use std::env;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc::{Client as BitcoinClient, RpcApi};
use clap::{Parser, Subcommand};
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_logging::TracingSetup;
use tokio::process::Command;
use tracing::{error, info, trace};
use url::Url;

#[derive(Subcommand)]
enum Cmd {
    Bitcoind,
    Lightningd,
    Lnd,
    Daemons,
}

#[derive(Parser)]
#[command(version)]
struct Args {
    #[clap(subcommand)]
    command: Cmd,
}

fn bitcoin_rpc() -> anyhow::Result<Arc<BitcoinClient>> {
    let url: Url = env::var("FM_TEST_BITCOIND_RPC")
        .expect("Must have bitcoind RPC defined for real tests")
        .parse()
        .expect("Invalid bitcoind RPC URL");
    let (host, auth) =
        fedimint_bitcoind::bitcoincore_rpc::from_url_to_url_auth(&url).expect("corrent url");
    let client =
        Arc::new(BitcoinClient::new(&host, auth).expect("couldn't create Bitcoin RPC client"));
    Ok(client)
}

async fn await_bitcoin_rpc(waiter_name: &str) -> anyhow::Result<()> {
    let rpc = bitcoin_rpc()?;

    while rpc.get_blockchain_info().is_err() {
        sleep(Duration::from_secs(1)).await;
        info!("{waiter_name} waiting for bitcoin rpc ...");
    }

    Ok(())
}

async fn run_bitcoind() -> anyhow::Result<()> {
    let btc_dir = env::var("FM_BTC_DIR").unwrap();

    // spawn bitcoind
    let mut bitcoind = Command::new("bitcoind")
        .arg(format!("-datadir={btc_dir}"))
        .spawn()
        .expect("failed to spawn");
    info!("bitcoind started");

    // create client
    let client = bitcoin_rpc()?;

    // create RPC wallet
    while let Err(e) = client.create_wallet("", None, None, None, None) {
        error!("Failed to create wallet ... retrying");
        trace!("{:?}", e);
        sleep(Duration::from_secs(1)).await
    }

    // mine blocks
    let address = client.get_new_address(None, None)?;
    client.generate_to_address(101, &address)?;

    bitcoind.wait().await?;

    Ok(())
}

async fn run_lightningd() -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoin_rpc("lightningd").await?;

    let cln_dir = env::var("FM_CLN_DIR").unwrap();
    let bin_dir = env::var("FM_BIN_DIR").unwrap();

    // spawn lightningd
    let mut lightningd = Command::new("lightningd")
        .arg("--dev-fast-gossip")
        .arg("--dev-bitcoind-poll=1")
        .arg(format!("--lightning-dir={cln_dir}"))
        .arg(format!("--plugin={bin_dir}/gateway-cln-extension"))
        .spawn()
        .expect("failed to spawn");
    info!("lightningd started");

    lightningd.wait().await?;

    Ok(())
}

async fn run_lnd() -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoin_rpc("lnd").await?;

    let lnd_dir = env::var("FM_LND_DIR").unwrap();

    // spawn lnd
    let mut lnd = Command::new("lnd")
        .arg(format!("--lnddir={lnd_dir}"))
        .spawn()
        .expect("failed to spawn");
    info!("lnd started");

    lnd.wait().await?;

    Ok(())
}

async fn daemons() -> anyhow::Result<()> {
    let mut root_task_group = TaskGroup::new();
    root_task_group.install_kill_handler();

    root_task_group
        .spawn("bitcoind", move |_| async move {
            run_bitcoind().await.expect("bitcoind failed")
        })
        .await;

    root_task_group
        .spawn("lightningd", move |_| async move {
            run_lightningd().await.expect("lightningd failed")
        })
        .await;

    root_task_group
        .spawn("lnd", move |_| async move {
            run_lnd().await.expect("lnd failed")
        })
        .await;

    root_task_group.join_all(None).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let args = Args::parse();
    match args.command {
        Cmd::Bitcoind => run_bitcoind().await.expect("bitcoind failed"),
        Cmd::Lightningd => run_lightningd().await.expect("lightningd failed"),
        Cmd::Lnd => run_lnd().await.expect("lnd failed"),
        Cmd::Daemons => daemons().await.expect("daemons failed"),
    }

    Ok(())
}
