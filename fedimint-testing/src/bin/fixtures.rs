/// This tool assumes that `scripts/build.sh` has been sourced in the
/// environment which calls it
use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bitcoincore_rpc::{Client as BitcoinClient, RpcApi};
use clap::{Parser, Subcommand};
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_logging::TracingSetup;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tracing::{error, info};
use url::Url;

#[derive(Subcommand)]
enum Cmd {
    // daemons
    Bitcoind,
    Federation { start_id: usize, stop_id: usize },

    // commands
    AwaitBitcoindReady,
}

#[derive(Parser)]
#[command(version)]
struct Args {
    #[clap(subcommand)]
    command: Cmd,
}

fn bitcoin_rpc() -> anyhow::Result<Arc<BitcoinClient>> {
    let url: Url = env::var("FM_TEST_BITCOIND_RPC")?.parse()?;
    let (host, auth) = fedimint_bitcoind::bitcoincore_rpc::from_url_to_url_auth(&url)?;
    let client = Arc::new(BitcoinClient::new(&host, auth)?);
    Ok(client)
}

/// Save PID to a $FM_PID_FILE which `kill_fedimint_processes` shell script
/// reads from and kills every PID it finds on EXIT
async fn kill_on_exit(name: &str, process: &Child) -> anyhow::Result<()> {
    let pid_file = env::var("FM_PID_FILE")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(pid_file)
        .await?;

    let mut buf = Vec::<u8>::new();
    writeln!(
        buf,
        "{}",
        process.id().ok_or_else(|| anyhow!("PID missing"))?
    )?;
    file.write_all(&buf).await?;

    // TODO: temporarily here, chasing shutdown hang
    info!(pid = process.id(), name, "Process pid added to FM_PID_FILE");

    Ok(())
}

async fn await_bitcoind_ready(waiter_name: &str) -> anyhow::Result<()> {
    let rpc = bitcoin_rpc()?;

    loop {
        if let Ok(info) = rpc.get_blockchain_info() {
            if info.blocks > 100 {
                break;
            }
        };
        info!("{waiter_name} waiting for bitcoind ...");
        sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

async fn run_bitcoind() -> anyhow::Result<()> {
    let btc_dir = env::var("FM_BTC_DIR")?;

    // spawn bitcoind
    let mut bitcoind = Command::new("bitcoind")
        .arg(format!("-datadir={btc_dir}"))
        .spawn()?;
    kill_on_exit("bitcoind", &bitcoind).await?;
    info!("bitcoind started");

    // create client
    let client = bitcoin_rpc()?;

    // create RPC wallet
    while let Err(e) = client.create_wallet("", None, None, None, None) {
        if e.to_string().contains("Database already exists") {
            break;
        }
        error!("Failed to create wallet ... retrying {}", e);
        sleep(Duration::from_secs(1)).await
    }

    // mine blocks
    let address = client.get_new_address(None, None)?;
    client.generate_to_address(101, &address)?;

    bitcoind.wait().await?;

    Ok(())
}

async fn run_fedimintd(id: usize) -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoind_ready(&format!("fedimint-{id}")).await?;

    let env_vars = fedimint_env(id)?;
    let data_dir = env_vars
        .get("FM_FEDIMINT_DATA_DIR")
        .ok_or_else(|| anyhow!("FM_P2P_URL not found"))?;

    // create datadir if it doesn't already exist
    fs::create_dir_all(&data_dir).await?;

    // spawn fedimintd
    let mut fedimintd = Command::new("fedimintd")
        .arg("--data-dir")
        .arg(data_dir)
        .envs(env_vars)
        .spawn()?;
    kill_on_exit("fedimintd", &fedimintd).await?;
    info!("fedimintd started");

    // TODO: pass in optional task group to this function and select on it to wait
    // for shutdown (because multiple can be spawned by run_federation)
    fedimintd.wait().await?;

    Ok(())
}

async fn run_federation(start_id: usize, stop_id: usize) -> anyhow::Result<()> {
    let mut task_group = TaskGroup::new();
    task_group.install_kill_handler();

    for id in start_id..stop_id {
        task_group
            .spawn(format!("fedimintd-{id}"), move |_| async move {
                info!("starting fedimintd-{}", id);
                run_fedimintd(id).await.expect("fedimintd failed");
                info!("started fedimintd-{}", id);
            })
            .await;
    }

    task_group.join_all(None).await?;

    Ok(())
}

/// Create a map of environment variables which fedimintd and DKG can use,
/// but which can't be defined by `build.sh` because multiple of these daemons
/// run concurrently with different values.
///
/// We allow ranges of 10 ports for each fedimintd / dkg instance starting from
/// 18173. Each port needed is incremented by 1 within this range.
///
/// * `id` - ID of the server. Used to calculate port numbers.
fn fedimint_env(id: usize) -> anyhow::Result<HashMap<String, String>> {
    let base_port = 8173 + 10000;
    let p2p_port = base_port + (id * 10);
    let api_port = base_port + (id * 10) + 1;
    let ui_port = base_port + (id * 10) + 2;
    let cfg_dir = env::var("FM_DATA_DIR")?;
    Ok(HashMap::from_iter([
        ("FM_BIND_P2P".into(), format!("127.0.0.1:{p2p_port}")),
        (
            "FM_P2P_URL".into(),
            format!("fedimint://127.0.0.1:{p2p_port}"),
        ),
        ("FM_BIND_API".into(), format!("127.0.0.1:{api_port}")),
        ("FM_API_URL".into(), format!("ws://127.0.0.1:{api_port}")),
        ("FM_LISTEN_UI".into(), format!("127.0.0.1:{ui_port}")),
        (
            "FM_FEDIMINT_DATA_DIR".into(),
            format!("{cfg_dir}/server-{id}"),
        ),
        ("FM_PASSWORD".into(), format!("pass{id}")),
    ]))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    // This tool assumes that `scripts/build.sh` has been sourced in the shell that
    // calls it. It uses environment variables set by `scripts/build.sh`. Exit
    // if they don't exit.
    if env::var("FM_TMP_DIR").is_err() {
        eprintln!("You must `source scripts/build.s` before running the `fixtures` tool");
        exit(1);
    };

    let args = Args::parse();
    match args.command {
        // daemons
        Cmd::Bitcoind => run_bitcoind().await.expect("bitcoind failed"),
        Cmd::Federation { start_id, stop_id } => run_federation(start_id, stop_id)
            .await
            .expect("federation failed"),
        // commands
        Cmd::AwaitBitcoindReady => await_bitcoind_ready("").await.expect("daemons failed"),
    }

    Ok(())
}
