use std::env;
use std::io::Write;
use std::path::PathBuf;
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
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
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
    Daemons,
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

async fn record_pid(process: &Child) -> anyhow::Result<()> {
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

    let bin_dir = env::var("FM_BIN_DIR").unwrap();
    let cfg_dir = env::var("FM_CFG_DIR").unwrap();

    // spawn fedimintd
    let mut fedimintd = Command::new(format!("{bin_dir}/fedimintd"))
        .arg(format!("{cfg_dir}/server-{id}"))
        .env("FM_PASSWORD", password)
        .spawn()
        .expect("failed to spawn fedimintd");
    record_pid(&fedimintd).await?;
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
    record_pid(&gatewayd).await?;
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
        // daemons
        Cmd::Bitcoind => run_bitcoind().await.expect("bitcoind failed"),
        Cmd::Lightningd => run_lightningd().await.expect("lightningd failed"),
        Cmd::Lnd => run_lnd().await.expect("lnd failed"),
        Cmd::Electrs => run_electrs().await.expect("electrs failed"),
        Cmd::Esplora => run_esplora().await.expect("esplora failed"),
        Cmd::Fedimintd { id } => run_fedimintd(id).await.expect("fedimitn failed"),
        Cmd::Gatewayd => run_gatewayd().await.expect("gatewayd failed"),
        Cmd::Federation { start_id, stop_id } => run_federation(start_id, stop_id)
            .await
            .expect("federation failed"),
        Cmd::Daemons => daemons().await.expect("daemons failed"),
        // commands
        Cmd::AwaitFedimintBlockSync => await_fedimint_block_sync().await.expect("daemons failed"),
    }

    Ok(())
}
