/// This tool assumes that `scripts/build.sh` has been sourced in the
/// environment which calls it
use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use bitcoincore_rpc::{Client as BitcoinClient, RpcApi};
use clap::{Parser, Subcommand, ValueEnum};
use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen};
use fedimint_core::config::load_from_file;
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
use fedimint_core::db::Database;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_ln_client::LightningClientGen;
use fedimint_logging::TracingSetup;
use fedimint_wallet_client::config::WalletClientConfig;
use fedimint_wallet_client::WalletClientGen;
use mint_client::modules::mint::MintClientGen;
use mint_client::{module_decode_stubs, Client, UserClient, UserClientConfig};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, info};
use url::Url;

#[allow(dead_code)]
#[derive(ValueEnum, Clone, Debug)]
pub enum GatewayNode {
    Cln,
    Lnd,
}

impl ToString for GatewayNode {
    fn to_string(&self) -> String {
        match self {
            GatewayNode::Cln => "cln".to_string(),
            GatewayNode::Lnd => "lnd".to_string(),
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    // daemons
    Bitcoind,
    Lightningd,
    Lnd,
    Electrs,
    Esplora,
    AllDaemons,
    Dkg { servers: usize },
    Fedimintd { id: usize },
    Gatewayd { node: GatewayNode },
    Federation { start_id: usize, stop_id: usize },

    // commands
    AwaitFedimintBlockSync,
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

async fn fedimint_client() -> anyhow::Result<UserClient> {
    let workdir: PathBuf = env::var("FM_CFG_DIR")?.parse()?;
    let cfg_path = workdir.join("client.json");
    let db_path = workdir.join("client.db");
    let cfg: UserClientConfig = load_from_file(&cfg_path)?;
    let db = fedimint_rocksdb::RocksDb::open(db_path)?;
    let decoders = module_decode_stubs();
    let db = Database::new(db, module_decode_stubs());
    let module_gens = ClientModuleGenRegistry::from(vec![
        DynClientModuleGen::from(WalletClientGen),
        DynClientModuleGen::from(MintClientGen),
        DynClientModuleGen::from(LightningClientGen),
    ]);
    Ok(Client::new(cfg.clone(), decoders, module_gens, db, Default::default()).await)
}

/// Save PID to a $FM_PID_FILE which `kill_fedimint_processes` shell script
/// reads from and kills every PID it finds on EXIT
async fn kill_on_exit(process: &Child) -> anyhow::Result<()> {
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

async fn await_fedimint_block_sync() -> anyhow::Result<()> {
    await_bitcoind_ready("await_fedimint_block_sync").await?;
    let fedimint_client = fedimint_client().await?;
    let wallet_cfg: WalletClientConfig = fedimint_client
        .config()
        .0
        .get_module(LEGACY_HARDCODED_INSTANCE_ID_WALLET)?;
    let finality_delay = wallet_cfg.finality_delay;
    let bitcoin_rpc = bitcoin_rpc()?;
    let bitcoin_block_height = bitcoin_rpc.get_blockchain_info()?.blocks;
    let expected_block_height = bitcoin_block_height - (finality_delay as u64);

    fedimint_client
        .await_consensus_block_height(expected_block_height)
        .await?;
    Ok(())
}

async fn run_bitcoind() -> anyhow::Result<()> {
    let project_root: PathBuf = env::var("FM_SRC_DIR")?.parse()?; 
    let btc_dir = env::var("FM_BTC_DIR")?;
    let conf_path = project_root.join("misc/test/bitcoin.conf");
    let conf_path_string = conf_path.to_str().context("path must be valid UTF-8")?;
    // Spawn bitcoind
    let mut bitcoind = Command::new("bitcoind")
        .arg(format!("-datadir={btc_dir}"))
        .arg(format!("-conf={conf_path_string}"))
        .spawn()?;
    kill_on_exit(&bitcoind).await?;
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

async fn run_lightningd() -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoind_ready("lightningd").await?;

    let cln_dir = env::var("FM_CLN_DIR")?;
    let bin_dir = env::var("FM_BIN_DIR")?;

    // spawn lightningd
    let mut lightningd = Command::new("lightningd")
        .arg("--dev-fast-gossip")
        .arg("--dev-bitcoind-poll=1")
        .arg(format!("--lightning-dir={cln_dir}"))
        .arg(format!("--plugin={bin_dir}/gateway-cln-extension"))
        .spawn()?;
    kill_on_exit(&lightningd).await?;
    info!("lightningd started");

    lightningd.wait().await?;

    Ok(())
}

async fn run_lnd() -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoind_ready("lnd").await?;

    let lnd_dir = env::var("FM_LND_DIR")?;

    // spawn lnd
    let mut lnd = Command::new("lnd")
        .arg(format!("--lnddir={lnd_dir}"))
        .spawn()?;
    kill_on_exit(&lnd).await?;
    info!("lnd started");

    lnd.wait().await?;

    Ok(())
}

async fn run_electrs() -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoind_ready("electrs").await?;

    let electrs_dir = env::var("FM_ELECTRS_DIR")?;

    // spawn electrs
    let mut electrs = Command::new("electrs")
        .arg(format!("--conf-dir={electrs_dir}"))
        .arg(format!("--db-dir={electrs_dir}"))
        .spawn()?;
    kill_on_exit(&electrs).await?;
    info!("electrs started");

    electrs.wait().await?;

    Ok(())
}

async fn run_esplora() -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoind_ready("esplora").await?;

    let daemon_dir = env::var("FM_BTC_DIR")?;
    let esplora_dir = env::var("FM_ESPLORA_DIR")?;

    // spawn esplora
    let mut esplora = Command::new("esplora")
        .arg(format!("--daemon-dir={daemon_dir}"))
        .arg(format!("--db-dir={esplora_dir}"))
        .arg("--cookie=bitcoin:bitcoin")
        .arg("--network=regtest")
        .arg("--daemon-rpc-addr=127.0.0.1:18443")
        .arg("--http-addr=127.0.0.1:50002")
        .arg("--monitoring-addr=127.0.0.1:50003")
        .spawn()?;
    kill_on_exit(&esplora).await?;
    info!("esplora started");

    esplora.wait().await?;

    Ok(())
}

async fn run_fedimintd(id: usize) -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoind_ready(&format!("fedimint-{id}")).await?;

    let bin_dir = env::var("FM_BIN_DIR")?;
    let env_vars = fedimint_env(id)?;
    let data_dir = env_vars
        .get("FM_FEDIMINT_DATA_DIR")
        .ok_or_else(|| anyhow!("FM_P2P_URL not found"))?;

    // create datadir if it doesn't already exist
    fs::create_dir_all(&data_dir).await?;

    // spawn fedimintd
    let mut fedimintd = Command::new(format!("{bin_dir}/fedimintd"))
        .arg("--data-dir")
        .arg(data_dir)
        .envs(env_vars)
        .spawn()?;
    kill_on_exit(&fedimintd).await?;
    info!("fedimintd started");

    // TODO: pass in optional task group to this function and select on it to wait
    // for shutdown (because multiple can be spawned by run_federation)
    fedimintd.wait().await?;

    Ok(())
}

async fn run_gatewayd(node: GatewayNode) -> anyhow::Result<()> {
    let bin_dir = env::var("FM_BIN_DIR")?;

    // TODO: await_fedimint_block_sync()

    let mut gatewayd = Command::new(format!("{bin_dir}/gatewayd"))
        .arg(node.to_string())
        .spawn()?;
    kill_on_exit(&gatewayd).await?;
    info!("gatewayd started");

    // TODO: connect_gateways

    gatewayd.wait().await?;

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
    let cfg_dir = env::var("FM_CFG_DIR")?;
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

async fn create_tls(id: usize, sender: Sender<String>) -> anyhow::Result<()> {
    // set env vars
    let bin_dir = env::var("FM_BIN_DIR")?;
    let server_name = format!("Server-{id}");
    let env_vars = fedimint_env(id)?;
    let p2p_url = env_vars
        .get("FM_P2P_URL")
        .ok_or_else(|| anyhow!("FM_P2P_URL not found"))?;
    let api_url = env_vars
        .get("FM_API_URL")
        .ok_or_else(|| anyhow!("FM_API_URL not found"))?;
    let out_dir = env_vars
        .get("FM_FEDIMINT_DATA_DIR")
        .ok_or_else(|| anyhow!("FM_FEDIMINT_DATA_DIR not found"))?;
    let cert_path = format!("{out_dir}/tls-cert");

    // create out-dir
    fs::create_dir(&out_dir).await?;

    info!("creating TLS certs created for started {server_name} in {out_dir}");
    let mut task = Command::new(format!("{bin_dir}/distributedgen"))
        .envs(fedimint_env(id)?)
        .arg("create-cert")
        .arg(format!("--p2p-url={p2p_url}"))
        .arg(format!("--api-url={api_url}"))
        .arg(format!("--out-dir={out_dir}"))
        .arg(format!("--name={server_name}"))
        .spawn()?;
    kill_on_exit(&task).await?;

    task.wait().await?;
    info!("TLS certs created for started {server_name}");

    // TODO: read TLS cert from disk and return if over channel
    let cert = fs::read_to_string(cert_path)
        .await
        .map_err(|_| anyhow!("Could not read TLS cert from disk"))?;
    sender
        .send(cert)
        .await
        .map_err(|_| anyhow!("failed to send cert over channel"))?;

    Ok(())
}

async fn run_distributedgen(id: usize, certs: Vec<String>) -> anyhow::Result<()> {
    let certs = certs.join(",");
    let bin_dir = env::var("FM_BIN_DIR")?;
    let cfg_dir = env::var("FM_CFG_DIR")?;
    let server_name = format!("Server-{id}");

    let env_vars = fedimint_env(id)?;
    let bind_p2p = env_vars
        .get("FM_BIND_P2P")
        .expect("fedimint_env sets this key");
    let bind_api = env_vars
        .get("FM_BIND_API")
        .expect("fedimint_env sets this key");
    let out_dir = env_vars
        .get("FM_FEDIMINT_DATA_DIR")
        .expect("fedimint_env sets this key");

    info!("creating TLS certs created for started {server_name} in {out_dir}");
    let mut task = Command::new(format!("{bin_dir}/distributedgen"))
        .envs(&env_vars)
        .arg("run")
        .arg(format!("--bind-p2p={bind_p2p}"))
        .arg(format!("--bind-api={bind_api}"))
        .arg(format!("--out-dir={out_dir}"))
        .arg(format!("--certs={certs}"))
        .spawn()
        .unwrap_or_else(|e| panic!("DKG failed for for {server_name} {e:?}"));
    kill_on_exit(&task).await?;

    task.wait().await?;
    info!("DKG created for started {server_name}");

    // copy configs to config directory
    fs::rename(
        format!("{out_dir}/client-connect"),
        format!("{cfg_dir}/client-connect"),
    )
    .await?;
    fs::rename(
        format!("{out_dir}/client.json"),
        format!("{cfg_dir}/client.json"),
    )
    .await?;
    info!("copied client configs");

    Ok(())
}

async fn run_dkg(servers: usize) -> anyhow::Result<()> {
    let root_task_group = TaskGroup::new();
    root_task_group.install_kill_handler();
    let mut task_group = root_task_group.make_subgroup().await;

    // generate TLS certs
    let (sender, mut receiver): (Sender<String>, Receiver<String>) = mpsc::channel(1000);
    for id in 0..servers {
        let sender = sender.clone();
        task_group
            .spawn(
                format!("create TLS certs for server {id}"),
                move |_| async move {
                    info!("generating certs for server {}", id);
                    create_tls(id, sender).await.expect("create_tls failed");
                    info!("generating certs for server {}", id);
                },
            )
            .await;
    }
    task_group.join_all(None).await?;
    info!("Generated TLS certs");

    // collect TLS certs
    let mut certs = vec![];
    while certs.len() < servers {
        let cert = receiver
            .recv()
            .await
            .expect("couldn't receive cert over channel");
        certs.push(cert)
    }
    let certs_string = certs.join(",");
    info!("Collected TLS certs: {certs_string}");

    // generate keys
    let mut task_group = root_task_group.make_subgroup().await;
    for id in 0..servers {
        let certs = certs.clone();
        task_group
            .spawn(
                format!("create TLS certs for server {id}"),
                move |_| async move {
                    info!("generating keys for server {}", id);
                    run_distributedgen(id, certs)
                        .await
                        .expect("run_distributedgen failed");
                    info!("generating keys for server {}", id);
                },
            )
            .await;
    }

    task_group.join_all(None).await?;
    info!("DKG complete");

    Ok(())
}

/// Run bitcoind, lightningd, lnd, electrs, esplora
async fn all_daemons() -> anyhow::Result<()> {
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
            run_electrs().await.expect("electrs failed")
        })
        .await;

    root_task_group
        .spawn("esplora", move |_| async move {
            run_esplora().await.expect("esplora failed")
        })
        .await;

    root_task_group.join_all(None).await?;

    Ok(())
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
        Cmd::Lightningd => run_lightningd().await.expect("lightningd failed"),
        Cmd::Lnd => run_lnd().await.expect("lnd failed"),
        Cmd::Electrs => run_electrs().await.expect("electrs failed"),
        Cmd::Esplora => run_esplora().await.expect("esplora failed"),
        Cmd::Fedimintd { id } => run_fedimintd(id).await.expect("fedimint failed"),
        Cmd::Gatewayd { node } => run_gatewayd(node).await.expect("gatewayd failed"),
        Cmd::Dkg { servers } => run_dkg(servers).await.expect("dkg failed"),
        Cmd::Federation { start_id, stop_id } => run_federation(start_id, stop_id)
            .await
            .expect("federation failed"),
        Cmd::AllDaemons => all_daemons().await.expect("daemons failed"),
        // commands
        Cmd::AwaitFedimintBlockSync => await_fedimint_block_sync().await.expect("daemons failed"),
        Cmd::AwaitBitcoindReady => await_bitcoind_ready("").await.expect("daemons failed"),
    }

    Ok(())
}
