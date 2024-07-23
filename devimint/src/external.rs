use std::ops::{ControlFlow, Deref as _};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bitcoincore_rpc::bitcoin::{Address, BlockHash};
use bitcoincore_rpc::bitcoincore_rpc_json::{GetBalancesResult, GetBlockchainInfoResult};
use bitcoincore_rpc::{bitcoin, RpcApi};
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use cln_rpc::ClnRpc;
use fedimint_core::encoding::Encodable;
use fedimint_core::task::jit::{JitTry, JitTryAnyhow};
use fedimint_core::task::{block_in_place, block_on, sleep, timeout};
use fedimint_core::util::write_overwrite_async;
use fedimint_core::BitcoinHash;
use fedimint_logging::LOG_DEVIMINT;
use fedimint_testing::gateway::LightningNodeType;
use hex::ToHex;
use tokio::fs;
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};
use tokio::time::Instant;
use tonic_lnd::lnrpc::{ChanInfoRequest, GetInfoRequest, ListChannelsRequest};
use tonic_lnd::Client as LndClient;
use tracing::{debug, info, trace, warn};

use crate::util::{poll, ClnLightningCli, ProcessHandle, ProcessManager};
use crate::vars::utf8;
use crate::version_constants::VERSION_0_4_0_ALPHA;
use crate::{cmd, poll_eq, Gatewayd};

#[derive(Clone)]
pub struct Bitcoind {
    pub client: Arc<bitcoincore_rpc::Client>,
    pub(crate) wallet_client: Arc<JitTryAnyhow<Arc<bitcoincore_rpc::Client>>>,
    pub(crate) _process: ProcessHandle,
}

impl Bitcoind {
    pub async fn new(processmgr: &ProcessManager, skip_setup: bool) -> Result<Self> {
        let btc_dir = utf8(&processmgr.globals.FM_BTC_DIR);

        // TODO(support:v0.3)
        // we need to run with txindex for versions before 0.4.0-alpha to correctly
        // process change outputs
        let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
        let tx_index = if fedimintd_version < *VERSION_0_4_0_ALPHA {
            "1"
        } else {
            "0"
        };

        let conf = format!(
            include_str!("cfg/bitcoin.conf"),
            rpc_port = processmgr.globals.FM_PORT_BTC_RPC,
            p2p_port = processmgr.globals.FM_PORT_BTC_P2P,
            zmq_pub_raw_block = processmgr.globals.FM_PORT_BTC_ZMQ_PUB_RAW_BLOCK,
            zmq_pub_raw_tx = processmgr.globals.FM_PORT_BTC_ZMQ_PUB_RAW_TX,
            tx_index = tx_index,
        );
        write_overwrite_async(processmgr.globals.FM_BTC_DIR.join("bitcoin.conf"), conf).await?;
        let process = processmgr
            .spawn_daemon(
                "bitcoind",
                cmd!(crate::util::Bitcoind, "-datadir={btc_dir}"),
            )
            .await?;

        let url = processmgr.globals.FM_BITCOIN_RPC_URL.parse()?;
        debug!("Parsed FM_BITCOIN_RPC_URL: {:?}", &url);
        let (host, auth) = fedimint_bitcoind::bitcoincore::from_url_to_url_auth(&url)?;
        debug!("bitcoind host: {:?}, auth: {:?}", &host, auth);
        let client =
            Self::new_bitcoin_rpc(&host, auth.clone()).context("Failed to connect to bitcoind")?;
        let wallet_client = JitTry::new_try(move || async move {
            let client =
                Self::new_bitcoin_rpc(&host, auth).context("Failed to connect to bitcoind")?;
            Self::init(&client, skip_setup).await?;
            Ok(Arc::new(client))
        });

        Ok(Self {
            _process: process,
            client: Arc::new(client),
            wallet_client: Arc::new(wallet_client),
        })
    }

    fn new_bitcoin_rpc(
        url: &str,
        auth: bitcoincore_rpc::Auth,
    ) -> anyhow::Result<bitcoincore_rpc::Client> {
        // The default (15s) is too low for some test environments
        const RPC_TIMEOUT: Duration = Duration::from_secs(45);
        let mut builder = bitcoincore_rpc::jsonrpc::simple_http::Builder::new()
            .url(url)?
            .timeout(RPC_TIMEOUT);
        let (user, pass) = auth.get_user_pass()?;
        if let Some(user) = user {
            builder = builder.auth(user, pass);
        }
        let client = bitcoincore_rpc::jsonrpc::Client::with_transport(builder.build());
        Ok(bitcoincore_rpc::Client::from_jsonrpc(client))
    }

    pub(crate) async fn init(client: &bitcoincore_rpc::Client, skip_setup: bool) -> Result<()> {
        debug!("Setting up bitcoind");
        // create RPC wallet
        for attempt in 0.. {
            match fedimint_core::runtime::block_in_place(|| {
                client.create_wallet("", None, None, None, None)
            }) {
                Ok(_) => {
                    break;
                }
                Err(err) => {
                    if err.to_string().contains("Database already exists") {
                        break;
                    }
                    if attempt % 20 == 19 {
                        debug!(target: LOG_DEVIMINT, %attempt, %err, "Waiting for initial bitcoind wallet initialization");
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }

        if !skip_setup {
            // mine blocks
            let blocks = 101;
            let address = block_in_place(|| client.get_new_address(None, None))?.assume_checked();
            debug!(target: LOG_DEVIMINT, blocks_num=blocks, %address, "Mining blocks to address");
            block_in_place(|| {
                client
                    .generate_to_address(blocks, &address)
                    .context("Failed to generate blocks")
            })?;
            trace!(target: LOG_DEVIMINT, blocks_num=blocks, %address, "Mining blocks to address complete");
        }

        // wait bitciond is ready
        poll("bitcoind", || async {
            let info = block_in_place(|| client.get_blockchain_info())
                .context("bitcoind getblockchaininfo")
                .map_err(ControlFlow::Continue)?;
            if info.blocks > 100 {
                Ok(())
            } else {
                Err(ControlFlow::Continue(anyhow!(
                    "not enough blocks: {}",
                    info.blocks
                )))
            }
        })
        .await?;
        debug!("Bitcoind ready");
        Ok(())
    }

    /// Poll until bitcoind rpc responds for basic commands
    pub async fn poll_ready(&self) -> anyhow::Result<()> {
        poll("bitcoind rpc ready", || async {
            self.get_block_count()
                .map_err(ControlFlow::Continue::<anyhow::Error, _>)?;
            Ok(())
        })
        .await
    }

    /// Client that can has wallet initialized, can generate internal addresses
    /// and send funds
    pub async fn wallet_client(&self) -> anyhow::Result<&Self> {
        self.wallet_client.get_try().await?;
        Ok(self)
    }

    /// Returns the total number of blocks in the chain.
    ///
    /// Fedimint's IBitcoindRpc considers block count the total number of
    /// blocks, where bitcoind's rpc returns the height. Since the genesis
    /// block has height 0, we need to add 1 to get the total block count.
    pub fn get_block_count(&self) -> Result<u64> {
        Ok(block_in_place(|| self.client.get_block_count())? + 1)
    }

    pub async fn mine_blocks_no_wait(&self, block_num: u64) -> Result<u64> {
        let start_time = Instant::now();
        debug!(target: LOG_DEVIMINT, ?block_num, "Mining bitcoin blocks");
        let addr = self.get_new_address().await?;
        let initial_block_count = self.get_block_count()?;
        self.generate_to_address(block_num, &addr).await?;
        debug!(target: LOG_DEVIMINT,
            elapsed_ms = %start_time.elapsed().as_millis(),
            ?block_num, "Mined blocks (no wait)");

        Ok(initial_block_count)
    }

    pub async fn mine_blocks(&self, block_num: u64) -> Result<()> {
        let start_time = Instant::now();
        debug!(target: LOG_DEVIMINT, ?block_num, "Mining bitcoin blocks");
        let addr = self.get_new_address().await?;
        let initial_block_count = self.get_block_count()?;
        self.generate_to_address(block_num, &addr).await?;
        while self.get_block_count()? < initial_block_count + block_num {
            trace!(target: LOG_DEVIMINT, ?block_num, "Waiting for blocks to be mined");
            sleep(Duration::from_millis(100)).await;
        }

        debug!(target: LOG_DEVIMINT,
            elapsed_ms = %start_time.elapsed().as_millis(),
            ?block_num, "Mined blocks");

        Ok(())
    }

    pub async fn send_to(&self, addr: String, amount: u64) -> Result<bitcoin::Txid> {
        debug!(target: LOG_DEVIMINT, amount, addr, "Sending funds from bitcoind");
        let amount = bitcoin::Amount::from_sat(amount);
        let tx = self
            .wallet_client()
            .await?
            .send_to_address(&bitcoin::Address::from_str(&addr)?.assume_checked(), amount)
            .await?;
        Ok(tx)
    }

    pub async fn get_txout_proof(&self, txid: &bitcoin::Txid) -> Result<String> {
        let proof = self.get_tx_out_proof(&[*txid], None).await?;
        Ok(proof.encode_hex())
    }

    pub fn get_raw_transaction(&self, txid: &bitcoin::Txid) -> Result<String> {
        let tx = block_in_place(|| self.client.get_raw_transaction(txid, None))?;
        let bytes = tx.consensus_encode_to_vec();
        Ok(bytes.encode_hex())
    }

    pub async fn get_new_address(&self) -> Result<Address> {
        let client = &self.wallet_client().await?;
        let addr = block_in_place(|| client.client.get_new_address(None, None))?.assume_checked();
        Ok(addr)
    }

    pub async fn generate_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<Vec<BlockHash>> {
        let client = &self.wallet_client().await?;
        Ok(block_in_place(|| {
            client.client.generate_to_address(block_num, address)
        })?)
    }

    pub async fn get_tx_out_proof(
        &self,
        txid: &[bitcoin::Txid],
        block_hash: Option<&BlockHash>,
    ) -> anyhow::Result<Vec<u8>> {
        let client = &self.wallet_client().await?;
        Ok(block_in_place(|| {
            client.client.get_tx_out_proof(txid, block_hash)
        })?)
    }

    pub fn get_blockchain_info(&self) -> anyhow::Result<GetBlockchainInfoResult> {
        Ok(block_in_place(|| self.client.get_blockchain_info())?)
    }

    pub async fn send_to_address(
        &self,
        addr: &Address,
        amount: bitcoin::Amount,
    ) -> anyhow::Result<bitcoin::Txid> {
        let client = self.wallet_client().await?;
        Ok(block_in_place(|| {
            client
                .client
                .send_to_address(addr, amount, None, None, None, None, None, None)
        })?)
    }

    pub(crate) async fn get_balances(&self) -> anyhow::Result<GetBalancesResult> {
        let client = self.wallet_client().await?;
        Ok(block_in_place(|| client.client.get_balances())?)
    }

    pub(crate) fn get_jsonrpc_client(&self) -> &bitcoincore_rpc::jsonrpc::Client {
        self.client.get_jsonrpc_client()
    }
}

const GATEWAY_CLN_EXTENSION: &str = "gateway-cln-extension";

pub struct LightningdProcessHandle(ProcessHandle);

impl LightningdProcessHandle {
    async fn terminate(&self) -> Result<()> {
        if self.0.is_running().await {
            let mut stop_plugins = cmd!(ClnLightningCli, "plugin", "stop", GATEWAY_CLN_EXTENSION);
            if let Err(e) = stop_plugins.out_string().await {
                warn!(
                    target: LOG_DEVIMINT,
                    "failed to terminate lightningd plugins: {e:?}"
                );
            }
            self.0.terminate().await
        } else {
            Ok(())
        }
    }
}

impl Drop for LightningdProcessHandle {
    fn drop(&mut self) {
        // Terminate cln in a controlled way, otherwise it may leave running processes.
        block_in_place(|| {
            if let Err(e) = block_on(self.terminate()) {
                warn!(target: LOG_DEVIMINT, "failed to terminate lightningd: {e:?}");
            }
        });
    }
}

#[derive(Clone)]
pub struct Lightningd {
    pub(crate) rpc: Arc<Mutex<ClnRpc>>,
    pub(crate) process: Arc<LightningdProcessHandle>,
    pub(crate) bitcoind: Bitcoind,
}

impl Lightningd {
    pub async fn new(process_mgr: &ProcessManager, bitcoind: Bitcoind) -> Result<Self> {
        let cln_dir = &process_mgr.globals.FM_CLN_DIR;
        let conf = format!(
            include_str!("cfg/lightningd.conf"),
            port = process_mgr.globals.FM_PORT_CLN,
            bitcoin_rpcport = process_mgr.globals.FM_PORT_BTC_RPC,
        );
        write_overwrite_async(process_mgr.globals.FM_CLN_DIR.join("config"), conf).await?;
        // workaround: will crash on start if it gets a bad response from
        // bitcoind
        bitcoind.poll_ready().await?;
        let process = Lightningd::start(process_mgr, cln_dir).await?;

        let socket_cln = cln_dir.join("regtest/lightning-rpc");
        poll("lightningd", || async {
            ClnRpc::new(socket_cln.clone())
                .await
                .context("connect to lightningd")
                .map_err(ControlFlow::Continue)
        })
        .await?;
        let rpc = ClnRpc::new(socket_cln).await?;
        Ok(Self {
            bitcoind,
            rpc: Arc::new(Mutex::new(rpc)),
            process: Arc::new(LightningdProcessHandle(process)),
        })
    }

    pub async fn start(process_mgr: &ProcessManager, cln_dir: &Path) -> Result<ProcessHandle> {
        let extension_path = cmd!("which", GATEWAY_CLN_EXTENSION)
            .out_string()
            .await
            .context("gateway-cln-extension not on path")?;
        let btc_dir = utf8(&process_mgr.globals.FM_BTC_DIR);
        let cmd = cmd!(
            crate::util::Lightningd,
            "--dev-fast-gossip",
            "--dev-bitcoind-poll=1",
            format!("--lightning-dir={}", utf8(cln_dir)),
            format!("--bitcoin-datadir={btc_dir}"),
            "--plugin={extension_path}"
        );

        process_mgr.spawn_daemon("lightningd", cmd).await
    }

    pub async fn request<R>(&self, request: R) -> Result<R::Response>
    where
        R: cln_rpc::model::TypedRequest + serde::Serialize + std::fmt::Debug,
        R::Response: serde::de::DeserializeOwned + std::fmt::Debug,
    {
        let mut rpc = self.rpc.lock().await;
        Ok(rpc.call_typed(&request).await?)
    }

    // TODO(tvolk131): Remove this method and instead use
    // `Gatewayd.wait_for_chain_sync()` once 0.4.0 is released
    pub async fn await_block_processing(&self) -> Result<()> {
        poll("lightningd block processing", || async {
            let btc_height = self
                .bitcoind
                .get_blockchain_info()
                .context("bitcoind getblockchaininfo")
                .map_err(ControlFlow::Continue)?
                .blocks;
            let lnd_height = self
                .request(cln_rpc::model::requests::GetinfoRequest {})
                .await
                .map_err(ControlFlow::Continue)?
                .blockheight;
            poll_eq!(u64::from(lnd_height), btc_height)
        })
        .await?;
        Ok(())
    }

    pub async fn pub_key(&self) -> Result<String> {
        Ok(self
            .request(cln_rpc::model::requests::GetinfoRequest {})
            .await?
            .id
            .to_string())
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }

    pub async fn invoice(
        &self,
        amount: u64,
        description: String,
        label: String,
    ) -> anyhow::Result<String> {
        let invoice = self
            .request(cln_rpc::model::requests::InvoiceRequest {
                amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(amount)),
                description,
                label,
                expiry: Some(60),
                fallbacks: None,
                preimage: None,
                cltv: None,
                deschashonly: None,
                exposeprivatechannels: None,
            })
            .await?
            .bolt11;
        Ok(invoice)
    }

    pub async fn pay_bolt11_invoice(&self, invoice: String) -> anyhow::Result<()> {
        let invoice_status = self
            .request(cln_rpc::model::requests::PayRequest {
                bolt11: invoice,
                amount_msat: None,
                label: None,
                riskfactor: None,
                maxfeepercent: None,
                retry_for: None,
                maxdelay: None,
                exemptfee: None,
                localinvreqid: None,
                exclude: None,
                maxfee: None,
                description: None,
                partial_msat: None,
            })
            .await?
            .status;

        anyhow::ensure!(matches!(
            invoice_status,
            cln_rpc::model::responses::PayStatus::COMPLETE
        ));

        Ok(())
    }

    pub async fn wait_any_bolt11_invoice(&self) -> anyhow::Result<()> {
        let invoice_status = self
            .request(cln_rpc::model::requests::WaitanyinvoiceRequest {
                lastpay_index: None,
                timeout: None,
            })
            .await?
            .status;
        anyhow::ensure!(matches!(
            invoice_status,
            cln_rpc::model::responses::WaitanyinvoiceStatus::PAID
        ));

        Ok(())
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
        // workaround: will crash on start if it gets a bad response from
        // bitcoind
        bitcoind.poll_ready().await?;
        let (process, client) = Lnd::start(process_mgr).await?;
        let this = Self {
            _bitcoind: bitcoind,
            client: Arc::new(Mutex::new(client)),
            process,
        };
        // wait for lnd rpc to be active
        poll("lnd_startup", || async {
            this.pub_key().await.map_err(ControlFlow::Continue)
        })
        .await?;
        Ok(this)
    }

    pub async fn start(process_mgr: &ProcessManager) -> Result<(ProcessHandle, LndClient)> {
        let conf = format!(
            include_str!("cfg/lnd.conf"),
            listen_port = process_mgr.globals.FM_PORT_LND_LISTEN,
            rpc_port = process_mgr.globals.FM_PORT_LND_RPC,
            rest_port = process_mgr.globals.FM_PORT_LND_REST,
            btc_rpc_port = process_mgr.globals.FM_PORT_BTC_RPC,
            zmq_pub_raw_block = process_mgr.globals.FM_PORT_BTC_ZMQ_PUB_RAW_BLOCK,
            zmq_pub_raw_tx = process_mgr.globals.FM_PORT_BTC_ZMQ_PUB_RAW_TX,
        );
        write_overwrite_async(process_mgr.globals.FM_LND_DIR.join("lnd.conf"), conf).await?;
        let cmd = cmd!(
            crate::util::Lnd,
            format!("--lnddir={}", utf8(&process_mgr.globals.FM_LND_DIR))
        );

        let process = process_mgr.spawn_daemon("lnd", cmd).await?;
        let lnd_rpc_addr = &process_mgr.globals.FM_LND_RPC_ADDR;
        let lnd_macaroon = &process_mgr.globals.FM_LND_MACAROON;
        let lnd_tls_cert = &process_mgr.globals.FM_LND_TLS_CERT;
        poll("wait for lnd files", || async {
            if fs::try_exists(lnd_tls_cert)
                .await
                .context("lnd tls cert")
                .map_err(ControlFlow::Continue)?
                && fs::try_exists(lnd_macaroon)
                    .await
                    .context("lnd macaroon")
                    .map_err(ControlFlow::Continue)?
            {
                Ok(())
            } else {
                Err(ControlFlow::Continue(anyhow!(
                    "lnd tls cert or lnd macaroon not found"
                )))
            }
        })
        .await?;

        let client = poll("lnd_connect", || async {
            tonic_lnd::connect(
                lnd_rpc_addr.clone(),
                lnd_tls_cert.clone(),
                lnd_macaroon.clone(),
            )
            .await
            .context("lnd connect")
            .map_err(ControlFlow::Continue)
        })
        .await?;

        Ok((process, client))
    }

    pub async fn lightning_client_lock(
        &self,
    ) -> Result<MappedMutexGuard<'_, tonic_lnd::LightningClient>> {
        let guard = self.client.lock().await;
        Ok(MutexGuard::map(guard, |client| client.lightning()))
    }

    pub async fn invoices_client_lock(
        &self,
    ) -> Result<MappedMutexGuard<'_, tonic_lnd::InvoicesClient>> {
        let guard = self.client.lock().await;
        Ok(MutexGuard::map(guard, |client| client.invoices()))
    }

    pub async fn pub_key(&self) -> Result<String> {
        Ok(self
            .lightning_client_lock()
            .await?
            .get_info(GetInfoRequest {})
            .await?
            .into_inner()
            .identity_pubkey)
    }

    // TODO(tvolk131): Remove this method and instead use
    // `Gatewayd.wait_for_chain_sync()` once 0.4.0 is released
    pub async fn await_block_processing(&self) -> Result<()> {
        poll("lnd block processing", || async {
            let synced = self
                .lightning_client_lock()
                .await
                .map_err(ControlFlow::Break)?
                .get_info(GetInfoRequest {})
                .await
                .context("lnd get_info")
                .map_err(ControlFlow::Continue)?
                .into_inner()
                .synced_to_chain;
            if synced {
                Ok(())
            } else {
                Err(ControlFlow::Continue(anyhow!("lnd not synced_to_chain")))
            }
        })
        .await?;
        Ok(())
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }

    pub async fn invoice(&self, amount: u64) -> anyhow::Result<(String, Vec<u8>)> {
        let add_invoice = self
            .lightning_client_lock()
            .await?
            .add_invoice(tonic_lnd::lnrpc::Invoice {
                value_msat: amount as i64,
                ..Default::default()
            })
            .await?
            .into_inner();
        let invoice = add_invoice.payment_request;
        let payment_hash = add_invoice.r_hash;
        Ok((invoice, payment_hash))
    }

    pub async fn pay_bolt11_invoice(&self, invoice: String) -> anyhow::Result<()> {
        let payment = self
            .lightning_client_lock()
            .await?
            .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
                payment_request: invoice.clone(),
                ..Default::default()
            })
            .await?
            .into_inner();
        let payment_status = self
            .lightning_client_lock()
            .await?
            .list_payments(tonic_lnd::lnrpc::ListPaymentsRequest {
                include_incomplete: true,
                ..Default::default()
            })
            .await?
            .into_inner()
            .payments
            .into_iter()
            .find(|p| p.payment_hash == payment.payment_hash.encode_hex::<String>())
            .context("payment not in list")?
            .status();
        anyhow::ensure!(payment_status == tonic_lnd::lnrpc::payment::PaymentStatus::Succeeded);

        Ok(())
    }

    pub async fn wait_bolt11_invoice(&self, payment_hash: Vec<u8>) -> anyhow::Result<()> {
        let invoice_status = self
            .lightning_client_lock()
            .await?
            .lookup_invoice(tonic_lnd::lnrpc::PaymentHash {
                r_hash: payment_hash,
                ..Default::default()
            })
            .await?
            .into_inner()
            .state();
        anyhow::ensure!(invoice_status == tonic_lnd::lnrpc::invoice::InvoiceState::Settled);

        Ok(())
    }

    pub async fn create_hold_invoice(
        &self,
        amount: u64,
    ) -> anyhow::Result<([u8; 32], String, cln_rpc::primitives::Sha256)> {
        let preimage = rand::random::<[u8; 32]>();
        let hash = {
            let mut engine = bitcoin::hashes::sha256::Hash::engine();
            bitcoin::hashes::HashEngine::input(&mut engine, &preimage);
            bitcoin::hashes::sha256::Hash::from_engine(engine)
        };
        let hold_request = self
            .invoices_client_lock()
            .await?
            .add_hold_invoice(tonic_lnd::invoicesrpc::AddHoldInvoiceRequest {
                value_msat: amount as i64,
                hash: hash.to_byte_array().to_vec(),
                ..Default::default()
            })
            .await?
            .into_inner();
        let payment_request = hold_request.payment_request;
        Ok((preimage, payment_request, hash))
    }

    pub async fn settle_hold_invoice(
        &self,
        preimage: [u8; 32],
        payment_hash: cln_rpc::primitives::Sha256,
    ) -> anyhow::Result<()> {
        let mut hold_invoice_subscription = self
            .invoices_client_lock()
            .await?
            .subscribe_single_invoice(tonic_lnd::invoicesrpc::SubscribeSingleInvoiceRequest {
                r_hash: payment_hash.to_byte_array().to_vec(),
            })
            .await?
            .into_inner();
        loop {
            const WAIT_FOR_INVOICE_TIMEOUT: Duration = Duration::from_secs(60);
            match timeout(
                WAIT_FOR_INVOICE_TIMEOUT,
                futures::StreamExt::next(&mut hold_invoice_subscription),
            )
            .await
            {
                Ok(Some(Ok(invoice))) => {
                    if invoice.state() == tonic_lnd::lnrpc::invoice::InvoiceState::Accepted {
                        break;
                    }
                    debug!("hold invoice payment state: {:?}", invoice.state());
                }
                Ok(Some(Err(e))) => {
                    bail!("error in invoice subscription: {e:?}");
                }
                Ok(None) => {
                    bail!("invoice subscription ended before invoice was accepted");
                }
                Err(_) => {
                    bail!("timed out waiting for invoice to be accepted")
                }
            }
        }

        self.invoices_client_lock()
            .await?
            .settle_invoice(tonic_lnd::invoicesrpc::SettleInvoiceMsg {
                preimage: preimage.to_vec(),
            })
            .await?;

        Ok(())
    }
}

// TODO(tvolk131): Remove this method and instead use
// `open_channel_between_gateways()` below once 0.4.0 is released
pub async fn open_channel(
    process_mgr: &ProcessManager,
    bitcoind: &Bitcoind,
    cln: &Lightningd,
    lnd: &Lnd,
) -> Result<()> {
    debug!(target: LOG_DEVIMINT, "Opening channel between gateways (the old way)");

    debug!(target: LOG_DEVIMINT, "Await block ln nodes block processing");
    tokio::try_join!(cln.await_block_processing(), lnd.await_block_processing())?;

    debug!(target: LOG_DEVIMINT, "Opening LN channel between the nodes...");
    let cln_addr = cln
        .request(cln_rpc::model::requests::NewaddrRequest { addresstype: None })
        .await?
        .bech32
        .context("bech32 should be present")?;

    bitcoind.send_to(cln_addr, 100_000_000).await?;
    bitcoind.mine_blocks(10).await?;

    let lnd_pubkey = lnd.pub_key().await?;
    let cln_pubkey = cln.pub_key().await?;

    cln.request(cln_rpc::model::requests::ConnectRequest {
        id: format!(
            "{}@127.0.0.1:{}",
            lnd_pubkey, process_mgr.globals.FM_PORT_LND_LISTEN
        ),
        host: None,
        port: None,
    })
    .await
    .context("connect request")?;

    poll("fund channel", || async {
        cln.request(cln_rpc::model::requests::FundchannelRequest {
            id: lnd_pubkey
                .parse()
                .context("failed to parse lnd pubkey")
                .map_err(ControlFlow::Break)?,
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
            channel_type: None,
        })
        .await
        .map_err(ControlFlow::Continue)
    })
    .await?;

    bitcoind.mine_blocks(10).await?;

    poll("Wait for channel update", || async {
        let mut lnd_client = lnd.client.lock().await;
        let channels = lnd_client
            .lightning()
            .list_channels(ListChannelsRequest {
                active_only: true,
                ..Default::default()
            })
            .await
            .context("lnd list channels")
            .map_err(ControlFlow::Break)?
            .into_inner();

        if let Some(channel) = channels
            .channels
            .iter()
            .find(|channel| channel.remote_pubkey == cln_pubkey)
        {
            let chan_info = lnd_client
                .lightning()
                .get_chan_info(ChanInfoRequest {
                    chan_id: channel.chan_id,
                })
                .await;

            match chan_info {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    debug!(%e, "Getting chan info failed");
                }
            }
        }

        Err(ControlFlow::Continue(anyhow!("channel not found")))
    })
    .await?;

    Ok(())
}

pub async fn open_channel_between_gateways(
    bitcoind: &Bitcoind,
    gw_a: &JitTryAnyhow<Arc<Gatewayd>>,
    gw_b: &JitTryAnyhow<Arc<Gatewayd>>,
) -> Result<()> {
    let gw_a = gw_a.get_try().await?.deref().clone();
    let gw_b = gw_b.get_try().await?.deref().clone();

    let funding_addr = gw_a.get_funding_address().await?;

    bitcoind.send_to(funding_addr, 100_000_000).await?;
    bitcoind.mine_blocks(10).await?;

    debug!(target: LOG_DEVIMINT, "Await block ln nodes block processing");
    tokio::try_join!(
        gw_a.wait_for_chain_sync(bitcoind),
        gw_b.wait_for_chain_sync(bitcoind)
    )?;

    debug!(target: LOG_DEVIMINT, "Opening LN channel between the nodes...");
    gw_a.open_channel(
        gw_b.lightning_pubkey().await?,
        gw_b.lightning_node_addr.clone(),
        10_000_000,
        Some(5_000_000),
    )
    .await?;

    bitcoind.mine_blocks(10).await?;

    let gw_a_node_pubkey = gw_a.lightning_pubkey().await?;

    poll("Wait for channel update", || async {
        let channels = gw_b
            .list_active_channels()
            .await
            .context("list channels")
            .map_err(ControlFlow::Break)?;

        if channels
            .iter()
            .any(|channel| channel.remote_pubkey == gw_a_node_pubkey)
        {
            return Ok(());
        }

        Err(ControlFlow::Continue(anyhow!("channel not found")))
    })
    .await?;

    Ok(())
}

#[derive(Clone)]
pub enum LightningNode {
    Cln(Lightningd),
    Lnd(Lnd),
    Ldk,
}

impl LightningNode {
    pub fn name(&self) -> LightningNodeType {
        match self {
            LightningNode::Cln(_) => LightningNodeType::Cln,
            LightningNode::Lnd(_) => LightningNodeType::Lnd,
            LightningNode::Ldk => LightningNodeType::Ldk,
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
        // workaround: will crash on start if it gets a bad response from
        // bitcoind
        bitcoind.poll_ready().await?;
        debug!(target: LOG_DEVIMINT, "Starting electrs");
        let electrs_dir = process_mgr
            .globals
            .FM_ELECTRS_DIR
            .to_str()
            .context("non utf8 path")?;

        let daemon_dir = &process_mgr.globals.FM_BTC_DIR.display();

        let conf = format!(
            include_str!("cfg/electrs.toml"),
            rpc_port = process_mgr.globals.FM_PORT_BTC_RPC,
            p2p_port = process_mgr.globals.FM_PORT_BTC_P2P,
            electrs_port = process_mgr.globals.FM_PORT_ELECTRS,
            monitoring_port = process_mgr.globals.FM_PORT_ELECTRS_MONITORING,
        );
        debug!("electrs conf: {:?}", conf);
        write_overwrite_async(
            process_mgr.globals.FM_ELECTRS_DIR.join("electrs.toml"),
            conf,
        )
        .await?;
        let cmd = cmd!(
            crate::util::Electrs,
            "--conf-dir={electrs_dir}",
            "--db-dir={electrs_dir}",
            "--daemon-dir={daemon_dir}"
        );
        let process = process_mgr.spawn_daemon("electrs", cmd).await?;
        debug!(target: LOG_DEVIMINT, "Electrs ready");

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
        // workaround: will crash(?) on start if it gets a bad response from
        // bitcoind
        bitcoind.poll_ready().await?;
        debug!("Starting esplora");
        let daemon_dir = process_mgr
            .globals
            .FM_BTC_DIR
            .to_str()
            .context("non utf8 path")?;
        let esplora_dir = process_mgr
            .globals
            .FM_ESPLORA_DIR
            .to_str()
            .context("non utf8 path")?;

        let btc_rpc_port = process_mgr.globals.FM_PORT_BTC_RPC;
        let esplora_port = process_mgr.globals.FM_PORT_ESPLORA;
        // spawn esplora
        let cmd = cmd!(
            crate::util::Esplora,
            "--daemon-dir={daemon_dir}",
            "--db-dir={esplora_dir}",
            "--cookie=bitcoin:bitcoin",
            "--network=regtest",
            "--daemon-rpc-addr=127.0.0.1:{btc_rpc_port}",
            "--http-addr=127.0.0.1:{esplora_port}",
            "--monitoring-addr=127.0.0.1:0",
            "--jsonrpc-import", // Workaround for incompatible on-disk format
        );
        let process = process_mgr.spawn_daemon("esplora", cmd).await?;

        Self::wait_for_ready(process_mgr).await?;
        debug!(target: LOG_DEVIMINT, "Esplora ready");

        Ok(Self {
            _bitcoind: bitcoind,
            _process: process,
        })
    }

    /// Wait until the server is able to respond to requests.
    async fn wait_for_ready(process_mgr: &ProcessManager) -> Result<()> {
        let client = esplora_client::Builder::new(&format!(
            "http://localhost:{}",
            process_mgr.globals.FM_PORT_ESPLORA
        ))
        .build_async()
        .expect("esplora client build failed");

        poll("esplora server ready", || async {
            client
                .get_fee_estimates()
                .await
                .map_err(|e| ControlFlow::Continue(anyhow::anyhow!(e)))?;

            Ok(())
        })
        .await?;

        Ok(())
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
    let bitcoind = Bitcoind::new(process_mgr, false).await?;
    let (cln, lnd, electrs, esplora) = tokio::try_join!(
        Lightningd::new(process_mgr, bitcoind.clone()),
        Lnd::new(process_mgr, bitcoind.clone()),
        Electrs::new(process_mgr, bitcoind.clone()),
        Esplora::new(process_mgr, bitcoind.clone()),
    )?;
    open_channel(process_mgr, &bitcoind, &cln, &lnd).await?;
    // make sure the bitcoind wallet is ready
    let _ = bitcoind.wallet_client().await?;
    info!(
        target: LOG_DEVIMINT,
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
