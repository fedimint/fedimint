/// This tool assumes that `scripts/build.sh` has been sourced in the
/// environment which calls it
use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc::{Client as BitcoinClient, RpcApi};
use clap::{Parser, Subcommand};
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
use tracing::{error, info, trace};
use url::Url;

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
    Gatewayd,
    Federation { start_id: usize, stop_id: usize },

    // commands
    AwaitFedimintBlockSync,
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

async fn fedimint_client() -> anyhow::Result<UserClient> {
    let workdir: PathBuf = env::var("FM_CFG_DIR").unwrap().parse()?;
    let cfg_path = workdir.join("client.json");
    let db_path = workdir.join("client.db");
    let cfg: UserClientConfig = load_from_file(&cfg_path).expect("Failed to parse config");
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
    let pid_file = env::var("FM_PID_FILE").unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(pid_file)
        .await?;

    let mut buf = Vec::<u8>::new();
    writeln!(buf, "{}", process.id().expect("PID missing"))?;
    file.write_all(&buf).await?;

    Ok(())
}

async fn await_bitcoin_rpc(waiter_name: &str) -> anyhow::Result<()> {
    let rpc = bitcoin_rpc()?;

    while rpc.get_blockchain_info().is_err() {
        sleep(Duration::from_secs(1)).await;
        info!("{waiter_name} waiting for bitcoin rpc ...");
    }

    Ok(())
}

async fn await_fedimint_block_sync() -> anyhow::Result<()> {
    // FIXME: make sure we've had at least 101 blocks ... probably best to call
    // await_bitcoin_rpc and do it there? but then the function has weird name ...
    let fedimint_client = fedimint_client().await?;
    let wallet_cfg: WalletClientConfig = fedimint_client
        .config()
        .0
        .get_module(LEGACY_HARDCODED_INSTANCE_ID_WALLET)
        .expect("Malformed wallet config");
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
    let btc_dir = env::var("FM_BTC_DIR").unwrap();

    // spawn bitcoind
    let mut bitcoind = Command::new("bitcoind")
        .arg(format!("-datadir={btc_dir}"))
        .spawn()
        .expect("failed to spawn bitcoind");
    kill_on_exit(&bitcoind).await?;
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
    kill_on_exit(&lightningd).await?;
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
    kill_on_exit(&lnd).await?;
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
    kill_on_exit(&electrs).await?;
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
    kill_on_exit(&esplora).await?;
    info!("esplora started");

    esplora.wait().await?;

    Ok(())
}

async fn run_fedimintd(id: usize) -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    await_bitcoin_rpc(&format!("fedimint-{id}")).await?;

    let bin_dir = env::var("FM_BIN_DIR").unwrap();
    let cfg_dir = env::var("FM_CFG_DIR").unwrap();

    // spawn fedimintd
    let mut fedimintd = Command::new(format!("{bin_dir}/fedimintd"))
        // TODO: $FM_FEDIMINTD_DATA_DIR
        .arg(format!("{cfg_dir}/server-{id}"))
        .envs(fedimintd_env(id))
        .spawn()
        .expect("failed to spawn fedimintd");
    kill_on_exit(&fedimintd).await?;
    info!("fedimintd started");

    // TODO: pass in optional task group to this function and select on it to wait
    // for shutdown (because multiple can be spawned by run_federation)
    fedimintd.wait().await?;

    Ok(())
}

async fn run_gatewayd() -> anyhow::Result<()> {
    let bin_dir = env::var("FM_BIN_DIR").unwrap();

    // TODO: await_fedimint_block_sync()

    let mut gatewayd = Command::new(format!("{bin_dir}/gatewayd"))
        .spawn()
        .expect("failed to spawn gatewayd");
    kill_on_exit(&gatewayd).await?;
    info!("gatewayd started");

    // TODO: gw_connect_fed

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

fn fedimintd_env(id: usize) -> HashMap<String, String> {
    let base_port = 8173 + 10000;
    let p2p_port = base_port + (id * 10);
    let api_port = base_port + (id * 10) + 1;
    let ui_port = base_port + (id * 10) + 2;
    let cfg_dir = env::var("FM_CFG_DIR").unwrap();
    HashMap::from_iter([
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
    ])
}

async fn create_tls(id: usize, sender: Sender<String>) -> anyhow::Result<()> {
    // set env vars
    let bin_dir = env::var("FM_BIN_DIR").unwrap();
    let server_name = format!("Server-{id}");
    let env_vars = fedimintd_env(id);
    let p2p_url = env_vars.get("FM_P2P_URL").unwrap();
    let api_url = env_vars.get("FM_API_URL").unwrap();
    let out_dir = env_vars.get("FM_FEDIMINT_DATA_DIR").unwrap();
    let cert_path = format!("{out_dir}/tls-cert");

    // create out-dir
    fs::create_dir(&out_dir).await?;

    info!("creating TLS certs created for started {server_name} in {out_dir}");
    let mut task = Command::new(format!("{bin_dir}/distributedgen"))
        .envs(fedimintd_env(id))
        .arg("create-cert")
        .arg(format!("--p2p-url={p2p_url}"))
        .arg(format!("--api-url={api_url}"))
        .arg(format!("--out-dir={out_dir}"))
        .arg(format!("--name={server_name}"))
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn create TLS certs for {server_name} {e:?}"));
    kill_on_exit(&task).await?;

    task.wait().await?;
    info!("TLS certs created for started {server_name}");

    // TODO: read TLS cert from disk and return if over channel
    let cert = fs::read_to_string(cert_path)
        .await
        .expect("couldn't read cert from disk");
    sender
        .send(cert)
        .await
        .expect("failed to send cert over channel");

    Ok(())
}

async fn run_distributedgen(id: usize, certs: Vec<String>) -> anyhow::Result<()> {
    let certs = certs.join(",");
    let bin_dir = env::var("FM_BIN_DIR").unwrap();
    let cfg_dir = env::var("FM_CFG_DIR").unwrap();
    let server_name = format!("Server-{id}");

    let env_vars = fedimintd_env(id);
    let bind_p2p = env_vars.get("FM_BIND_P2P").unwrap();
    let bind_api = env_vars.get("FM_BIND_API").unwrap();
    let out_dir = env_vars.get("FM_FEDIMINT_DATA_DIR").unwrap();

    info!("creating TLS certs created for started {server_name} in {out_dir}");
    let mut task = Command::new(format!("{bin_dir}/distributedgen"))
        .envs(fedimintd_env(id))
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

    // let base_port = 8173 + 10000;
    // let mut certs = vec![];

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
        Cmd::Gatewayd => run_gatewayd().await.expect("gatewayd failed"),
        Cmd::Dkg { servers } => run_dkg(servers).await.expect("dkg failed"),
        Cmd::Federation { start_id, stop_id } => run_federation(start_id, stop_id)
            .await
            .expect("federation failed"),
        Cmd::AllDaemons => all_daemons().await.expect("daemons failed"),
        // commands
        Cmd::AwaitFedimintBlockSync => await_fedimint_block_sync().await.expect("daemons failed"),
    }

    Ok(())
}
