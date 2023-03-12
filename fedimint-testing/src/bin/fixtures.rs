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
    Electrs,
    Esplora,
    Daemons,
    Fedimintd { id: usize },
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
        .expect("failed to spawn bitcoind");
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
        .expect("failed to spawn lightningd");
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
        .expect("failed to spawn lnd");
    info!("lnd started");

    lnd.wait().await?;

    Ok(())
}

async fn run_electrs() -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoin_rpc("electrs").await?;

    let electrs_dir = env::var("FM_ELECTRS_DIR").unwrap();

    // spawn electrs
    let mut electrs = Command::new("electrs")
        .arg(format!("--conf-dir={electrs_dir}"))
        .arg(format!("--db-dir={electrs_dir}"))
        .spawn()
        .expect("failed to spawn electrs");
    info!("electrs started");

    electrs.wait().await?;

    Ok(())
}

async fn run_esplora() -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoin_rpc("esplora").await?;

    let daemon_dir = env::var("FM_BTC_DIR").unwrap();
    let test_dir = env::var("FM_TEST_DIR").unwrap();

    // spawn esplora
    let mut esplora = Command::new("esplora")
        .arg(format!("--daemon-dir={daemon_dir}"))
        .arg(format!("--db-dir={test_dir}/esplora"))
        .arg("--cookie=bitcoin:bitcoin")
        .arg("--network=regtest")
        .arg("--daemon-rpc-addr=127.0.0.1:18443")
        .arg("--http-addr=127.0.0.1:50002")
        .arg("--monitoring-addr=127.0.0.1:50003")
        .spawn()
        .expect("failed to spawn esplora");
    info!("esplora started");

    esplora.wait().await?;

    Ok(())
}

async fn run_fedimintd(id: usize) -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoin_rpc(&format!("fedimint-{id}")).await?;

    // set password env var
    let password = format!("pass{id}");
    env::set_var("FM_PASSWORD", password);

    let bin_dir = env::var("FM_BIN_DIR").unwrap();
    let cfg_dir = env::var("FM_CFG_DIR").unwrap();

    // spawn fedimintd
    let mut fedimintd = Command::new(format!("{bin_dir}/fedimintd"))
        .arg(format!("{cfg_dir}/server-{id}"))
        .spawn()
        .expect("failed to spawn fedimintd");
    info!("fedimintd started");

    fedimintd.wait().await?;

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

    root_task_group
        .spawn("electrs", move |_| async move {
            run_lnd().await.expect("electrs failed")
        })
        .await;

    root_task_group
        .spawn("esplora", move |_| async move {
            run_lnd().await.expect("esplora failed")
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
        Cmd::Electrs => run_electrs().await.expect("electrs failed"),
        Cmd::Esplora => run_esplora().await.expect("esplora failed"),
        Cmd::Fedimintd { id } => run_fedimintd(id).await.expect("esplora failed"),
        Cmd::Daemons => daemons().await.expect("daemons failed"),
    }

    Ok(())
}
