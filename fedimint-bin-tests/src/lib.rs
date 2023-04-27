use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::hashes::hex::ToHex;
use bitcoincore_rpc::{bitcoin, RpcApi};
use cln_rpc::ClnRpc;
use federation::{run_dkg, Federation};
use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen};
use fedimint_client_legacy::modules::mint::MintClientGen;
use fedimint_client_legacy::{module_decode_stubs, UserClient, UserClientConfig};
use fedimint_core::config::load_from_file;
use fedimint_core::db::Database;
use fedimint_core::encoding::Encodable;
use fedimint_core::task::TaskGroup;
use fedimint_ln_client::LightningClientGen;
use fedimint_wallet_client::WalletClientGen;
use tokio::fs;
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};
use tokio::time::sleep;
use tonic_lnd::lnrpc::GetInfoRequest;
use tracing::{info, warn};

pub mod util;
use util::*;
mod federation;

pub struct DevFed {
    pub bitcoind: Bitcoind,
    pub cln: Lightningd,
    pub lnd: Lnd,
    pub fed: Federation,
    pub gw_cln: Gatewayd,
    pub gw_lnd: Gatewayd,
    pub electrs: Electrs,
    pub esplora: Esplora,
}

#[derive(Clone)]
pub struct Bitcoind {
    client: Arc<bitcoincore_rpc::Client>,
    _process: ProcessHandle,
}

impl Bitcoind {
    pub async fn new(processmgr: &ProcessManager) -> Result<Self> {
        let btc_dir = env::var("FM_BTC_DIR")?;
        let process = processmgr
            .spawn_daemon("bitcoind", cmd!("bitcoind", "-datadir={btc_dir}"))
            .await?;

        let url = env::var("FM_TEST_BITCOIND_RPC")?.parse()?;
        let (host, auth) = fedimint_bitcoind::bitcoincore_rpc::from_url_to_url_auth(&url)?;
        let client = Arc::new(bitcoincore_rpc::Client::new(&host, auth)?);

        Self::init(&client).await?;
        Ok(Self {
            _process: process,
            client,
        })
    }

    async fn init(client: &bitcoincore_rpc::Client) -> Result<()> {
        // create RPC wallet
        while let Err(e) = client.create_wallet("", None, None, None, None) {
            if e.to_string().contains("Database already exists") {
                break;
            }
            warn!("Failed to create wallet ... retrying {}", e);
            sleep(Duration::from_secs(1)).await
        }

        // mine blocks
        let address = client.get_new_address(None, None)?;
        client.generate_to_address(101, &address)?;

        // wait bitciond is ready
        poll("bitcoind", || async {
            Ok(client
                .get_blockchain_info()
                .map_or(false, |info| (info.blocks > 100)))
        })
        .await?;
        Ok(())
    }

    pub fn client(&self) -> Arc<bitcoincore_rpc::Client> {
        self.client.clone()
    }

    pub async fn mine_blocks(&self, amt: u64) -> Result<()> {
        let client = self.client();
        let addr = client.get_new_address(None, None)?;
        client.generate_to_address(amt, &addr)?;
        Ok(())
    }

    pub async fn send_to(&self, addr: String, amt: u64) -> Result<bitcoin::Txid> {
        let amt = bitcoin::Amount::from_sat(amt);
        let tx = self.client().send_to_address(
            &bitcoin::Address::from_str(&addr)?,
            amt,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        Ok(tx)
    }

    pub async fn get_txout_proof(&self, txid: &bitcoin::Txid) -> Result<String> {
        let proof = self.client().get_tx_out_proof(&[*txid], None)?;
        Ok(proof.to_hex())
    }

    pub async fn get_raw_transaction(&self, txid: &bitcoin::Txid) -> Result<String> {
        let tx = self.client().get_raw_transaction(txid, None)?;
        let bytes = tx.consensus_encode_to_vec()?;
        Ok(bytes.to_hex())
    }
}

#[derive(Clone)]
pub struct Lightningd {
    rpc: Arc<Mutex<ClnRpc>>,
    _process: ProcessHandle,
    bitcoind: Bitcoind,
}

impl Lightningd {
    pub async fn new(process_mgr: &ProcessManager, bitcoind: Bitcoind) -> Result<Self> {
        let cln_dir = env::var("FM_CLN_DIR")?;

        let extension_path = cmd!("which", "gateway-cln-extension")
            .out_string()
            .await
            .context("gateway-cln-extension not on path")?;
        let cmd = cmd!(
            "lightningd",
            "--dev-fast-gossip",
            "--dev-bitcoind-poll=1",
            "--lightning-dir={cln_dir}",
            "--plugin={extension_path}"
        );

        let process = process_mgr.spawn_daemon("lightningd", cmd).await?;

        let socket_cln = PathBuf::from(cln_dir).join("regtest/lightning-rpc");
        poll("lightningd", || async {
            Ok(fs::try_exists(&socket_cln).await?)
        })
        .await?;
        let rpc = ClnRpc::new(socket_cln).await?;
        Ok(Self {
            bitcoind,
            rpc: Arc::new(Mutex::new(rpc)),
            _process: process,
        })
    }

    pub async fn request<R: cln_rpc::model::IntoRequest>(&self, request: R) -> Result<R::Response>
    where
        R::Response: Send,
    {
        let mut rpc = self.rpc.lock().await;
        Ok(rpc.call_typed(request).await?)
    }

    pub async fn await_block_processing(&self) -> Result<()> {
        poll("lightningd block processing", || async {
            let btc_height = self.bitcoind.client().get_blockchain_info()?.blocks;
            let lnd_height = self
                .request(cln_rpc::model::GetinfoRequest {})
                .await?
                .blockheight;
            Ok((lnd_height as u64) == btc_height)
        })
        .await?;
        Ok(())
    }

    pub async fn pub_key(&self) -> Result<String> {
        Ok(self
            .request(cln_rpc::model::GetinfoRequest {})
            .await?
            .id
            .to_string())
    }
}

#[derive(Clone)]
pub struct Lnd {
    client: Arc<Mutex<tonic_lnd::LndClient>>,
    _process: ProcessHandle,
    _bitcoind: Bitcoind,
}

impl Lnd {
    pub async fn new(process_mgr: &ProcessManager, bitcoind: Bitcoind) -> Result<Self> {
        let lnd_dir = env::var("FM_LND_DIR")?;
        let cmd = cmd!("lnd", "--lnddir={lnd_dir}");

        let process = process_mgr.spawn_daemon("lnd", cmd).await?;
        let lnd_rpc_addr = env::var("FM_LND_RPC_ADDR")?;
        let lnd_macaroon = env::var("FM_LND_MACAROON")?;
        let lnd_tls_cert = env::var("FM_LND_TLS_CERT")?;
        poll("lnd", || async {
            Ok(fs::try_exists(&lnd_tls_cert).await? && fs::try_exists(&lnd_macaroon).await?)
        })
        .await?;
        let client = tonic_lnd::connect(
            lnd_rpc_addr.clone(),
            lnd_tls_cert.clone(),
            lnd_macaroon.clone(),
        )
        .await?;
        let this = Self {
            _bitcoind: bitcoind,
            client: Arc::new(Mutex::new(client)),
            _process: process,
        };
        // wait for lnd rpc to be active
        poll("lnd", || async { Ok(this.pub_key().await.is_ok()) }).await?;
        Ok(this)
    }

    pub async fn client_lock(&self) -> Result<MappedMutexGuard<'_, tonic_lnd::LightningClient>> {
        let guard = self.client.lock().await;
        Ok(MutexGuard::map(guard, |client| client.lightning()))
    }

    pub async fn pub_key(&self) -> Result<String> {
        Ok(self
            .client_lock()
            .await?
            .get_info(GetInfoRequest {})
            .await?
            .into_inner()
            .identity_pubkey)
    }

    pub async fn await_block_processing(&self) -> Result<()> {
        poll("lnd block processing", || async {
            Ok(self
                .client_lock()
                .await?
                .get_info(GetInfoRequest {})
                .await?
                .into_inner()
                .synced_to_chain)
        })
        .await?;
        Ok(())
    }
}

pub async fn open_channel(bitcoind: &Bitcoind, cln: &Lightningd, lnd: &Lnd) -> Result<()> {
    tokio::try_join!(cln.await_block_processing(), lnd.await_block_processing())?;
    info!("block sync done");
    let cln_addr = cln
        .request(cln_rpc::model::NewaddrRequest { addresstype: None })
        .await?
        .bech32
        .context("bech32 should be present")?;

    bitcoind.send_to(cln_addr, 100_000_000).await?;
    bitcoind.mine_blocks(10).await?;

    let lnd_pubkey = lnd.pub_key().await?;

    cln.request(cln_rpc::model::ConnectRequest {
        id: lnd_pubkey.parse()?,
        host: Some("127.0.0.1".to_owned()),
        port: Some(9734),
    })
    .await?;

    poll("fund channel", || async {
        Ok(cln
            .request(cln_rpc::model::FundchannelRequest {
                id: lnd_pubkey.parse()?,
                amount: cln_rpc::primitives::AmountOrAll::Amount(
                    cln_rpc::primitives::Amount::from_sat(10_000_000),
                ),
                push_msat: Some(cln_rpc::primitives::Amount::from_sat(5_000_000)),
                feerate: None,
                announce: None,
                minconf: None,
                close_to: None,
                request_amt: None,
                compact_lease: None,
                utxos: None,
                mindepth: None,
                reserve: None,
            })
            .await
            .is_ok())
    })
    .await?;

    poll("list peers", || async {
        Ok(!cln
            .request(cln_rpc::model::ListpeersRequest {
                id: Some(lnd_pubkey.parse()?),
                level: None,
            })
            .await?
            .peers
            .is_empty())
    })
    .await?;
    bitcoind.mine_blocks(10).await?;
    Ok(())
}

#[derive(Clone)]
pub enum ClnOrLnd {
    Cln(Lightningd),
    Lnd(Lnd),
}

impl ClnOrLnd {
    fn name(&self) -> &'static str {
        match self {
            ClnOrLnd::Cln(_) => "cln",
            ClnOrLnd::Lnd(_) => "lnd",
        }
    }
}

#[derive(Clone)]
pub struct Gatewayd {
    _process: ProcessHandle,
    ln: ClnOrLnd,
}

impl Gatewayd {
    pub async fn new(process_mgr: &ProcessManager, ln: ClnOrLnd) -> Result<Self> {
        let ln_name = ln.name();
        let test_dir = env::var("FM_TEST_DIR")?;
        let gateway_env: HashMap<String, String> = match ln {
            ClnOrLnd::Cln(_) => HashMap::from_iter([
                (
                    "FM_GATEWAY_DATA_DIR".to_owned(),
                    format!("{test_dir}/gw-cln"),
                ),
                (
                    "FM_GATEWAY_LISTEN_ADDR".to_owned(),
                    "127.0.0.1:8175".to_owned(),
                ),
                (
                    "FM_GATEWAY_API_ADDR".to_owned(),
                    "http://127.0.0.1:8175".to_owned(),
                ),
            ]),
            ClnOrLnd::Lnd(_) => HashMap::from_iter([
                (
                    "FM_GATEWAY_DATA_DIR".to_owned(),
                    format!("{test_dir}/gw-lnd"),
                ),
                (
                    "FM_GATEWAY_LISTEN_ADDR".to_owned(),
                    "127.0.0.1:28175".to_owned(),
                ),
                (
                    "FM_GATEWAY_API_ADDR".to_owned(),
                    "http://127.0.0.1:28175".to_owned(),
                ),
            ]),
        };
        let process = process_mgr
            .spawn_daemon(
                &format!("gatewayd-{ln_name}"),
                cmd!("gatewayd", ln_name).envs(gateway_env),
            )
            .await?;

        Ok(Self {
            ln,
            _process: process,
        })
    }

    pub async fn cmd(&self) -> Command {
        match &self.ln {
            ClnOrLnd::Cln(_) => {
                cmd!("gateway-cli", "--rpcpassword=theresnosecondbest")
            }
            ClnOrLnd::Lnd(_) => {
                cmd!(
                    "gateway-cli",
                    "--rpcpassword=theresnosecondbest",
                    "-a",
                    "http://127.0.0.1:28175"
                )
            }
        }
    }

    pub async fn connect_fed(&self, fed: &Federation) -> Result<()> {
        let connect_str = poll_value("connect info", || async {
            match cmd!(fed, "connect-info").out_json().await {
                Ok(info) => Ok(Some(
                    info["connect_info"]
                        .as_str()
                        .context("connect_info must be string")?
                        .to_owned(),
                )),
                Err(_) => Ok(None),
            }
        })
        .await?;
        poll("gateway connect-fed", || async {
            Ok(cmd!(self, "connect-fed", connect_str.clone())
                .run()
                .await
                .is_ok())
        })
        .await?;
        Ok(())
    }
}

pub async fn dev_fed(task_group: &TaskGroup, process_mgr: &ProcessManager) -> Result<DevFed> {
    let start_time = fedimint_core::time::now();
    let bitcoind = Bitcoind::new(process_mgr).await?;
    let ((cln, lnd, gw_cln, gw_lnd), electrs, esplora, fed) = tokio::try_join!(
        async {
            let (cln, lnd) = tokio::try_join!(
                Lightningd::new(process_mgr, bitcoind.clone()),
                Lnd::new(process_mgr, bitcoind.clone())
            )?;
            info!("lightning started");
            let (gw_cln, gw_lnd, _) = tokio::try_join!(
                Gatewayd::new(process_mgr, ClnOrLnd::Cln(cln.clone())),
                Gatewayd::new(process_mgr, ClnOrLnd::Lnd(lnd.clone())),
                open_channel(&bitcoind, &cln, &lnd),
            )?;
            info!("gateways started");
            Ok((cln, lnd, gw_cln, gw_lnd))
        },
        Electrs::new(process_mgr, bitcoind.clone()),
        Esplora::new(process_mgr, bitcoind.clone()),
        async {
            run_dkg(task_group, 4).await?;
            info!("dkg done");
            Federation::new(process_mgr, bitcoind.clone(), 0..4).await
        },
    )?;
    info!("federation and gateways started");
    tokio::try_join!(gw_cln.connect_fed(&fed), gw_lnd.connect_fed(&fed))?;
    fed.await_gateways_registered().await?;
    info!("gateways registered");
    fed.use_gateway(&gw_cln).await?;
    info!("starting dev federation took {:?}", start_time.elapsed()?);
    Ok(DevFed {
        bitcoind,
        cln,
        lnd,
        fed,
        gw_cln,
        gw_lnd,
        electrs,
        esplora,
    })
}

#[derive(Clone)]
pub struct Electrs {
    _process: ProcessHandle,
    _bitcoind: Bitcoind,
}

impl Electrs {
    pub async fn new(process_mgr: &ProcessManager, bitcoind: Bitcoind) -> Result<Self> {
        let electrs_dir = env::var("FM_ELECTRS_DIR")?;

        let cmd = cmd!(
            "electrs",
            "--conf-dir={electrs_dir}",
            "--db-dir={electrs_dir}",
        );
        let process = process_mgr.spawn_daemon("electrs", cmd).await?;
        info!("electrs started");

        Ok(Self {
            _bitcoind: bitcoind,
            _process: process,
        })
    }
}

#[derive(Clone)]
pub struct Esplora {
    _process: ProcessHandle,
    _bitcoind: Bitcoind,
}

impl Esplora {
    pub async fn new(process_mgr: &ProcessManager, bitcoind: Bitcoind) -> Result<Self> {
        let daemon_dir = env::var("FM_BTC_DIR")?;
        let esplora_dir = env::var("FM_ESPLORA_DIR")?;

        // spawn esplora
        let cmd = cmd!(
            "esplora",
            "--daemon-dir={daemon_dir}",
            "--db-dir={esplora_dir}",
            "--cookie=bitcoin:bitcoin",
            "--network=regtest",
            "--daemon-rpc-addr=127.0.0.1:18443",
            "--http-addr=127.0.0.1:50002",
            "--monitoring-addr=127.0.0.1:50003",
        );
        let process = process_mgr.spawn_daemon("esplora", cmd).await?;
        info!("esplora started");

        Ok(Self {
            _bitcoind: bitcoind,
            _process: process,
        })
    }
}
