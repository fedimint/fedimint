use std::env;
use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc::{Client as BitcoinClient, RpcApi};
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_logging::TracingSetup;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{error, info, trace};
use url::Url;

#[derive(Default, Clone)]
struct State {
    bitcoin_rpc: bool,
}

impl State {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Clone)]
struct MutableState(Arc<Mutex<State>>);

impl MutableState {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(State::new())))
    }
    async fn state(&self) -> State {
        (*self.0.lock().await).clone()
    }
    async fn await_bitcoin_rpc(&self, waiter_name: &str) {
        loop {
            if self.state().await.bitcoin_rpc {
                break;
            }
            sleep(Duration::from_secs(1)).await;
            info!("{waiter_name} waiting for bitcoin rpc ...");
        }
    }
    async fn bitcoin_rpc_ready(&self) {
        self.0.lock().await.bitcoin_rpc = true;
        info!("bitcoind ready");
    }
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

async fn run_bitcoind(state: MutableState) -> anyhow::Result<()> {
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

    // update state so other services know bitcoin rpc is ready
    state.bitcoin_rpc_ready().await;

    bitcoind.wait().await?;

    Ok(())
}

async fn run_lightningd(state: MutableState) -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    state.await_bitcoin_rpc("lightningd").await;

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

async fn run_lnd(state: MutableState) -> anyhow::Result<()> {
    // wait for bitcoin RPC to be ready ...
    state.await_bitcoin_rpc("lnd").await;

    let lnd_dir = env::var("FM_LND_DIR").unwrap();

    // spawn lnd
    let mut lightningd = Command::new("lnd")
        .arg(format!("--lnddir={lnd_dir}"))
        .spawn()
        .expect("failed to spawn");
    info!("lnd started");

    lightningd.wait().await?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let state = MutableState::new();

    let mut root_task_group = TaskGroup::new();
    root_task_group.install_kill_handler();

    let bitcoind_state = state.clone();
    root_task_group
        .spawn("bitcoind", move |_| async move {
            run_bitcoind(bitcoind_state).await.expect("bitcoind failed")
        })
        .await;

    let lightningd_state = state.clone();
    root_task_group
        .spawn("lightningd", move |_| async move {
            run_lightningd(lightningd_state)
                .await
                .expect("lightningd failed")
        })
        .await;

    let lnd_state = state.clone();
    root_task_group
        .spawn("lnd", move |_| async move {
            run_lnd(lnd_state).await.expect("lnd failed")
        })
        .await;

    root_task_group.join_all(None).await?;

    Ok(())
}
