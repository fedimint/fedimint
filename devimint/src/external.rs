use std::env;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoincore_rpc::bitcoin::hashes::hex::ToHex;
use bitcoincore_rpc::{bitcoin, RpcApi};
use cln_rpc::ClnRpc;
use fedimint_core::encoding::Encodable;
use fedimint_core::task::sleep;
use fedimint_logging::LOG_DEVIMINT;
use tokio::fs;
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};
use tonic_lnd::lnrpc::GetInfoRequest;
use tonic_lnd::Client as LndClient;
use tracing::{info, warn};

use crate::cmd;
use crate::util::{poll, ProcessHandle, ProcessManager};
use crate::vars::utf8;

#[derive(Clone)]
pub struct Bitcoind {
    pub(crate) client: Arc<bitcoincore_rpc::Client>,
    pub(crate) _process: ProcessHandle,
}

impl Bitcoind {
    pub async fn new(processmgr: &ProcessManager) -> Result<Self> {
        let btc_dir = utf8(&processmgr.globals.FM_BTC_DIR);
        let process = processmgr
            .spawn_daemon("bitcoind", cmd!("bitcoind", "-datadir={btc_dir}"))
            .await?;

        let url = processmgr.globals.FM_BITCOIN_RPC_URL.parse()?;
        let (host, auth) = fedimint_bitcoind::bitcoincore::from_url_to_url_auth(&url)?;
        let client = Arc::new(bitcoincore_rpc::Client::new(&host, auth)?);

        Self::init(&client).await?;
        Ok(Self {
            _process: process,
            client,
        })
    }

    pub(crate) async fn init(client: &bitcoincore_rpc::Client) -> Result<()> {
        // create RPC wallet
        while let Err(e) = client.create_wallet("", None, None, None, None) {
            if e.to_string().contains("Database already exists") {
                break;
            }
            warn!(LOG_DEVIMINT, "Failed to create wallet ... retrying {}", e);
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

    pub async fn mine_blocks(&self, block_num: u64) -> Result<()> {
        info!(block_num, "Mining bitcoin blocks");
        let client = self.client();
        let addr = client.get_new_address(None, None)?;
        client.generate_to_address(block_num, &addr)?;
        Ok(())
    }

    pub async fn send_to(&self, addr: String, amount: u64) -> Result<bitcoin::Txid> {
        info!(amount, addr, "Sending funds from bitcoind");
        let amount = bitcoin::Amount::from_sat(amount);
        let tx = self.client().send_to_address(
            &bitcoin::Address::from_str(&addr)?,
            amount,
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

    pub async fn get_new_address(&self) -> Result<String> {
        let addr = self.client().get_new_address(None, None)?;
        Ok(addr.to_string())
    }
}

#[derive(Clone)]
pub struct Lightningd {
    pub(crate) rpc: Arc<Mutex<ClnRpc>>,
    pub(crate) process: ProcessHandle,
    pub(crate) bitcoind: Bitcoind,
}

impl Lightningd {
    pub async fn new(process_mgr: &ProcessManager, bitcoind: Bitcoind) -> Result<Self> {
        let cln_dir = &process_mgr.globals.FM_CLN_DIR;
        let process = Lightningd::start(process_mgr, cln_dir).await?;

        let socket_cln = cln_dir.join("regtest/lightning-rpc");
        poll("lightningd", || async {
            Ok(ClnRpc::new(socket_cln.clone()).await.is_ok())
        })
        .await?;
        let rpc = ClnRpc::new(socket_cln).await?;
        Ok(Self {
            bitcoind,
            rpc: Arc::new(Mutex::new(rpc)),
            process,
        })
    }

    pub async fn start(process_mgr: &ProcessManager, cln_dir: &Path) -> Result<ProcessHandle> {
        let extension_path = cmd!("which", "gateway-cln-extension")
            .out_string()
            .await
            .context("gateway-cln-extension not on path")?;
        let btc_dir = utf8(&process_mgr.globals.FM_BTC_DIR);
        let cmd = cmd!(
            "lightningd",
            "--dev-fast-gossip",
            "--dev-bitcoind-poll=1",
            format!("--lightning-dir={}", utf8(cln_dir)),
            format!("--bitcoin-datadir={btc_dir}"),
            "--plugin={extension_path}"
        );

        process_mgr.spawn_daemon("lightningd", cmd).await
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

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }
}

#[derive(Clone)]
pub struct Lnd {
    pub(crate) client: Arc<Mutex<LndClient>>,
    pub(crate) process: ProcessHandle,
    pub(crate) _bitcoind: Bitcoind,
}

impl Lnd {
    pub async fn new(process_mgr: &ProcessManager, bitcoind: Bitcoind) -> Result<Self> {
        let (process, client) = Lnd::start(process_mgr).await?;
        let this = Self {
            _bitcoind: bitcoind,
            client: Arc::new(Mutex::new(client)),
            process,
        };
        // wait for lnd rpc to be active
        poll("lnd", || async { Ok(this.pub_key().await.is_ok()) }).await?;
        Ok(this)
    }

    pub async fn start(process_mgr: &ProcessManager) -> Result<(ProcessHandle, LndClient)> {
        let cmd = cmd!(
            "lnd",
            format!("--lnddir={}", utf8(&process_mgr.globals.FM_LND_DIR))
        );

        let process = process_mgr.spawn_daemon("lnd", cmd).await?;
        let lnd_rpc_addr = &process_mgr.globals.FM_LND_RPC_ADDR;
        let lnd_macaroon = &process_mgr.globals.FM_LND_MACAROON;
        let lnd_tls_cert = &process_mgr.globals.FM_LND_TLS_CERT;
        poll("lnd", || async {
            Ok(fs::try_exists(lnd_tls_cert).await? && fs::try_exists(lnd_macaroon).await?)
        })
        .await?;

        poll("lnd_connect", || async {
            Ok(tonic_lnd::connect(
                lnd_rpc_addr.clone(),
                lnd_tls_cert.clone(),
                lnd_macaroon.clone(),
            )
            .await
            .is_ok())
        })
        .await?;

        let client = tonic_lnd::connect(
            lnd_rpc_addr.clone(),
            lnd_tls_cert.clone(),
            lnd_macaroon.clone(),
        )
        .await?;
        Ok((process, client))
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

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }
}

pub async fn open_channel(bitcoind: &Bitcoind, cln: &Lightningd, lnd: &Lnd) -> Result<()> {
    tokio::try_join!(cln.await_block_processing(), lnd.await_block_processing())?;
    info!(LOG_DEVIMINT, "block sync done");
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
pub enum LightningNode {
    Cln(Lightningd),
    Lnd(Lnd),
}

impl LightningNode {
    pub fn name(&self) -> LightningNodeName {
        match self {
            LightningNode::Cln(_) => LightningNodeName::Cln,
            LightningNode::Lnd(_) => LightningNodeName::Lnd,
        }
    }
}

#[derive(Debug)]
pub enum LightningNodeName {
    Cln,
    Lnd,
}

impl Display for LightningNodeName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            LightningNodeName::Cln => write!(f, "cln"),
            LightningNodeName::Lnd => write!(f, "lnd"),
        }
    }
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
        info!(LOG_DEVIMINT, "electrs started");

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
            "--jsonrpc-import", // Workaround for incompatible on-disk format
        );
        let process = process_mgr.spawn_daemon("esplora", cmd).await?;
        info!(target: LOG_DEVIMINT, "esplora started");

        Ok(Self {
            _bitcoind: bitcoind,
            _process: process,
        })
    }
}

#[allow(unused)]
pub struct ExternalDaemons {
    pub bitcoind: Bitcoind,
    pub cln: Lightningd,
    pub lnd: Lnd,
    pub electrs: Electrs,
    pub esplora: Esplora,
}

pub async fn external_daemons(process_mgr: &ProcessManager) -> Result<ExternalDaemons> {
    let start_time = fedimint_core::time::now();
    let bitcoind = Bitcoind::new(process_mgr).await?;
    let (cln, lnd, electrs, esplora) = tokio::try_join!(
        Lightningd::new(process_mgr, bitcoind.clone()),
        Lnd::new(process_mgr, bitcoind.clone()),
        Electrs::new(process_mgr, bitcoind.clone()),
        Esplora::new(process_mgr, bitcoind.clone()),
    )?;
    open_channel(&bitcoind, &cln, &lnd).await?;
    info!(
        LOG_DEVIMINT,
        "starting base daemons took {:?}",
        start_time.elapsed()?
    );
    Ok(ExternalDaemons {
        bitcoind,
        cln,
        lnd,
        electrs,
        esplora,
    })
}
