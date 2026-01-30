use std::ops::ControlFlow;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::hashes::{Hash, sha256};
use bitcoincore_rpc::bitcoin::{Address, BlockHash};
use bitcoincore_rpc::bitcoincore_rpc_json::{GetBalancesResult, GetBlockchainInfoResult};
use bitcoincore_rpc::jsonrpc::error::RpcError;
use bitcoincore_rpc::{Auth, RpcApi};
use fedimint_core::encoding::Encodable;
use fedimint_core::rustls::install_crypto_provider;
use fedimint_core::task::jit::{JitTry, JitTryAnyhow};
use fedimint_core::task::{block_in_place, sleep, timeout};
use fedimint_core::util::backoff_util::api_networking_backoff;
use fedimint_core::util::{FmtCompact as _, SafeUrl, retry, write_overwrite_async};
use fedimint_logging::LOG_DEVIMINT;
use fedimint_testing_core::node_type::LightningNodeType;
use futures::StreamExt;
use hex::ToHex;
use itertools::Itertools;
use tokio::fs;
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};
use tokio::task::spawn_blocking;
use tokio::time::Instant;
use tonic_lnd::Client as LndClient;
use tonic_lnd::lnrpc::GetInfoRequest;
use tonic_lnd::routerrpc::SendPaymentRequest;
use tracing::{debug, info, trace, warn};

use crate::util::{ProcessHandle, ProcessManager, poll};
use crate::vars::utf8;
use crate::{Gatewayd, cmd};

#[derive(Clone)]
pub struct Bitcoind {
    pub client: Arc<bitcoincore_rpc::Client>,
    pub(crate) wallet_client: Arc<JitTryAnyhow<Arc<bitcoincore_rpc::Client>>>,
    pub(crate) _process: ProcessHandle,
}

impl Bitcoind {
    pub async fn new(processmgr: &ProcessManager, skip_setup: bool) -> Result<Self> {
        let btc_dir = utf8(&processmgr.globals.FM_BTC_DIR);

        let conf = format!(
            include_str!("cfg/bitcoin.conf"),
            rpc_port = processmgr.globals.FM_PORT_BTC_RPC,
            p2p_port = processmgr.globals.FM_PORT_BTC_P2P,
            zmq_pub_raw_block = processmgr.globals.FM_PORT_BTC_ZMQ_PUB_RAW_BLOCK,
            zmq_pub_raw_tx = processmgr.globals.FM_PORT_BTC_ZMQ_PUB_RAW_TX,
            tx_index = "0",
        );
        write_overwrite_async(processmgr.globals.FM_BTC_DIR.join("bitcoin.conf"), conf).await?;
        let process = processmgr
            .spawn_daemon(
                "bitcoind",
                cmd!(crate::util::Bitcoind, "-datadir={btc_dir}"),
            )
            .await?;

        let url: SafeUrl = processmgr.globals.FM_BITCOIN_RPC_URL.parse()?;

        debug!("Parsed FM_BITCOIN_RPC_URL: {:?}", &url);

        let auth = Auth::UserPass(
            url.username().to_owned(),
            url.password()
                .context("Bitcoin RPC URL is missing password")?
                .to_owned(),
        );

        let host = url
            .without_auth()
            .map_err(|()| anyhow!("Failed to strip auth from Bitcoin Rpc Url"))?
            .to_string();
        let wallet_name = "";
        let host = format!("{host}wallet/{wallet_name}");

        debug!(target: LOG_DEVIMINT, "bitcoind host: {:?}, auth: {:?}", &host, auth);
        let client =
            Self::new_bitcoin_rpc(&host, auth.clone()).context("Failed to connect to bitcoind")?;
        let wallet_client = JitTry::new_try(move || async move {
            let client =
                Self::new_bitcoin_rpc(&host, auth).context("Failed to connect to bitcoind")?;
            Self::init(&client, skip_setup).await?;
            Ok(Arc::new(client))
        });

        let bitcoind = Self {
            _process: process,
            client: Arc::new(client),
            wallet_client: Arc::new(wallet_client),
        };

        bitcoind.poll_ready().await?;

        // To have a ChainId we always need at least one block.
        let addr = bitcoind.get_new_address().await?;
        bitcoind.generate_to_address(1, addr).await?;

        Ok(bitcoind)
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
        debug!(target: LOG_DEVIMINT, "Setting up bitcoind...");
        // create RPC wallet
        for attempt in 0.. {
            match block_in_place(|| client.create_wallet("", None, None, None, None)) {
                Ok(_) => {
                    break;
                }
                Err(err) => {
                    if err.to_string().contains("Database already exists") {
                        break;
                    }
                    if attempt % 20 == 19 {
                        debug!(target: LOG_DEVIMINT, %attempt, err = %err.fmt_compact(), "Waiting for initial bitcoind wallet initialization");
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }

        if !skip_setup {
            // mine blocks
            let blocks = 101;
            let address = block_in_place(|| client.get_new_address(None, None))?
                .require_network(bitcoin::Network::Regtest)
                .expect("Devimint always runs in regtest");
            debug!(target: LOG_DEVIMINT, blocks_num=blocks, %address, "Mining blocks to address");
            block_in_place(|| {
                client
                    .generate_to_address(blocks, &address)
                    .context("Failed to generate blocks")
            })?;
            trace!(target: LOG_DEVIMINT, blocks_num=blocks, %address, "Mining blocks to address complete");
        }

        // wait bitcoind is ready
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
    async fn poll_ready(&self) -> anyhow::Result<()> {
        poll("bitcoind rpc ready", || async {
            self.get_block_count()
                .await
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
    pub async fn get_block_count(&self) -> Result<u64> {
        let client = self.client.clone();
        Ok(spawn_blocking(move || client.get_block_count()).await?? + 1)
    }

    pub async fn mine_blocks_no_wait(&self, block_num: u64) -> Result<u64> {
        let start_time = Instant::now();
        debug!(target: LOG_DEVIMINT, ?block_num, "Mining bitcoin blocks");
        let addr = self.get_new_address().await?;
        let initial_block_count = self.get_block_count().await?;
        self.generate_to_address(block_num, addr).await?;
        debug!(target: LOG_DEVIMINT,
            elapsed_ms = %start_time.elapsed().as_millis(),
            ?block_num, "Mined blocks (no wait)");

        Ok(initial_block_count)
    }

    pub async fn mine_blocks(&self, block_num: u64) -> Result<()> {
        // `Stdio::piped` can't even parse outputs larger
        // than pipe buffer size (64K on Linux, 16K on MacOS), so
        // we should split larger requesteds into smaller chunks.
        //
        // On top of it mining a lot of blocks is just slow, so should
        // be avoided.
        const BLOCK_NUM_LIMIT: u64 = 32;

        if BLOCK_NUM_LIMIT < block_num {
            warn!(
                target: LOG_DEVIMINT,
                %block_num,
                "Mining a lot of blocks (even when split) is a terrible idea and can lead to issues. Splitting request just to make it work somehow."
            );
            let mut block_num = block_num;

            loop {
                if BLOCK_NUM_LIMIT < block_num {
                    block_num -= BLOCK_NUM_LIMIT;
                    Box::pin(async { self.mine_blocks(BLOCK_NUM_LIMIT).await }).await?;
                } else {
                    Box::pin(async { self.mine_blocks(block_num).await }).await?;
                    return Ok(());
                }
            }
        }
        let start_time = Instant::now();
        debug!(target: LOG_DEVIMINT, ?block_num, "Mining bitcoin blocks");
        let addr = self.get_new_address().await?;
        let initial_block_count = self.get_block_count().await?;
        self.generate_to_address(block_num, addr).await?;
        while self.get_block_count().await? < initial_block_count + block_num {
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
            .send_to_address(
                bitcoin::Address::from_str(&addr)?
                    .require_network(bitcoin::Network::Regtest)
                    .expect("Devimint always runs in regtest"),
                amount,
            )
            .await?;
        Ok(tx)
    }

    pub async fn get_txout_proof(&self, txid: bitcoin::Txid) -> Result<String> {
        let client = self.wallet_client().await?.clone();
        let proof = spawn_blocking(move || client.client.get_tx_out_proof(&[txid], None)).await??;
        Ok(proof.encode_hex())
    }

    /// Poll a transaction by its txid until it is found in the mempool or in a
    /// block.
    pub async fn poll_get_transaction(&self, txid: bitcoin::Txid) -> anyhow::Result<String> {
        poll("Waiting for transaction in mempool", || async {
            match self
                .get_transaction(txid)
                .await
                .context("getrawtransaction")
            {
                Ok(Some(tx)) => Ok(tx),
                Ok(None) => Err(ControlFlow::Continue(anyhow::anyhow!(
                    "Transaction not found yet"
                ))),
                Err(err) => Err(ControlFlow::Break(err)),
            }
        })
        .await
    }

    /// Get a transaction by its txid. Checks the mempool and all blocks.
    async fn get_transaction(&self, txid: bitcoin::Txid) -> Result<Option<String>> {
        // Check the mempool.
        match self.get_raw_transaction(txid, None).await {
            // The RPC succeeded, and the transaction was not found in the mempool. Continue to
            // check blocks.
            Ok(None) => {}
            // The RPC failed, or the transaction was found in the mempool. Return the result.
            other => return other,
        }

        let block_height = self.get_block_count().await? - 1;

        // Check each block for the tx, starting at the chain tip.
        // Buffer the requests to avoid spamming bitcoind.
        // We're doing this after checking the mempool since the tx should
        // usually be in the mempool, and we don't want to needlessly hit
        // the bitcoind with block requests.
        let mut buffered_tx_stream = futures::stream::iter((0..block_height).rev())
            .map(|height| async move {
                let block_hash = self.get_block_hash(height).await?;
                self.get_raw_transaction(txid, Some(block_hash)).await
            })
            .buffered(32);

        while let Some(tx_or) = buffered_tx_stream.next().await {
            match tx_or {
                // The RPC succeeded, and the transaction was not found in the block. Continue to
                // the next block.
                Ok(None) => {}
                // The RPC failed, or the transaction was found in the block. Return the result.
                other => return other,
            }
        }

        // The transaction was not found in the mempool or any block.
        Ok(None)
    }

    async fn get_raw_transaction(
        &self,
        txid: bitcoin::Txid,
        block_hash: Option<BlockHash>,
    ) -> Result<Option<String>> {
        let client = self.client.clone();
        let tx_or =
            spawn_blocking(move || client.get_raw_transaction(&txid, block_hash.as_ref())).await?;

        let tx = match tx_or {
            Ok(tx) => tx,
            // `getrawtransaction` returns a JSON-RPC error with code -5 if the command
            // reaches bitcoind but is not found. See here:
            // https://github.com/bitcoin/bitcoin/blob/25dacae9c7feb31308271e2fd5a127c1fc230c2f/src/rpc/rawtransaction.cpp#L360-L376
            // https://github.com/bitcoin/bitcoin/blob/25dacae9c7feb31308271e2fd5a127c1fc230c2f/src/rpc/protocol.h#L42
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(
                RpcError { code: -5, .. },
            ))) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let bytes = tx.consensus_encode_to_vec();
        Ok(Some(bytes.encode_hex()))
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let client = self.client.clone();
        Ok(spawn_blocking(move || client.get_block_hash(height)).await??)
    }

    pub async fn get_new_address(&self) -> Result<Address> {
        let client = self.wallet_client().await?.clone();
        let addr = spawn_blocking(move || client.client.get_new_address(None, None))
            .await??
            .require_network(bitcoin::Network::Regtest)
            .expect("Devimint always runs in regtest");
        Ok(addr)
    }

    pub async fn generate_to_address(
        &self,
        block_num: u64,
        address: Address,
    ) -> Result<Vec<BlockHash>> {
        let client = self.wallet_client().await?.clone();
        Ok(
            spawn_blocking(move || client.client.generate_to_address(block_num, &address))
                .await??,
        )
    }

    pub async fn get_blockchain_info(&self) -> anyhow::Result<GetBlockchainInfoResult> {
        let client = self.client.clone();
        Ok(spawn_blocking(move || client.get_blockchain_info()).await??)
    }

    pub async fn send_to_address(
        &self,
        addr: Address,
        amount: bitcoin::Amount,
    ) -> anyhow::Result<bitcoin::Txid> {
        let client = self.wallet_client().await?.clone();

        let raw_client = client.client.clone();
        let txid = spawn_blocking(move || {
            raw_client.send_to_address(&addr, amount, None, None, None, None, None, None)
        })
        .await??;

        // Downstream code expects that mining blocks will include this
        // tx. Seems like this is not always immediately the case in Bitcoin Knobs.
        retry(
            "await-genesis-tx-processed".to_string(),
            api_networking_backoff(),
            || async {
                if client.get_transaction(txid).await?.is_none() {
                    bail!("Genesis tx not visible yet = {}", txid);
                }

                Ok(())
            },
        )
        .await
        .expect("Number of retries has no limit");
        Ok(txid)
    }

    pub(crate) async fn get_balances(&self) -> anyhow::Result<GetBalancesResult> {
        let client = self.wallet_client().await?.clone();
        Ok(spawn_blocking(move || client.client.get_balances()).await??)
    }

    pub(crate) fn get_jsonrpc_client(&self) -> &bitcoincore_rpc::jsonrpc::Client {
        self.client.get_jsonrpc_client()
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

        install_crypto_provider().await;

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

    pub async fn router_client_lock(
        &self,
    ) -> Result<MappedMutexGuard<'_, tonic_lnd::RouterClient>> {
        let guard = self.client.lock().await;
        Ok(MutexGuard::map(guard, |client| client.router()))
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
        let mut payment = self
            .router_client_lock()
            .await?
            .send_payment_v2(SendPaymentRequest {
                payment_request: invoice.clone(),
                ..Default::default()
            })
            .await?
            .into_inner();

        while let Some(update) = payment.message().await? {
            match update.status() {
                tonic_lnd::lnrpc::payment::PaymentStatus::Succeeded => return Ok(()),
                tonic_lnd::lnrpc::payment::PaymentStatus::InFlight => {}
                _ => return Err(anyhow!("LND lightning payment failed")),
            }
        }

        Err(anyhow!("LND lightning payment unknown status"))
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
    ) -> anyhow::Result<([u8; 32], String, sha256::Hash)> {
        let preimage = rand::random::<[u8; 32]>();
        let hash = {
            let mut engine = bitcoin::hashes::sha256::Hash::engine();
            bitcoin::hashes::HashEngine::input(&mut engine, &preimage);
            bitcoin::hashes::sha256::Hash::from_engine(engine)
        };
        let cltv_expiry = 650;
        let hold_request = self
            .invoices_client_lock()
            .await?
            .add_hold_invoice(tonic_lnd::invoicesrpc::AddHoldInvoiceRequest {
                value_msat: amount as i64,
                hash: hash.to_byte_array().to_vec(),
                cltv_expiry,
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
        payment_hash: sha256::Hash,
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

pub type NamedGateway<'a> = (&'a Gatewayd, &'a str);

#[allow(clippy::similar_names)]
pub async fn open_channels_between_gateways(
    bitcoind: &Bitcoind,
    gateways: &[NamedGateway<'_>],
) -> Result<()> {
    let block_height = bitcoind.get_block_count().await? - 1;
    debug!(target: LOG_DEVIMINT, ?block_height, "Syncing gateway lightning nodes to block height...");
    futures::future::try_join_all(
        gateways
            .iter()
            .map(|(gw, _gw_name)| gw.wait_for_block_height(block_height)),
    )
    .await?;

    info!(target: LOG_DEVIMINT, "Funding all gateway lightning nodes...");
    for (gw, _gw_name) in gateways {
        let funding_addr = gw.get_ln_onchain_address().await?;
        bitcoind.send_to(funding_addr, 100_000_000).await?;
    }

    bitcoind.mine_blocks(10).await?;

    info!(target: LOG_DEVIMINT, "Gateway lightning nodes funded.");

    let block_height = bitcoind.get_block_count().await? - 1;
    debug!(target: LOG_DEVIMINT, ?block_height, "Syncing gateway lightning nodes to block height...");
    futures::future::try_join_all(
        gateways
            .iter()
            .map(|(gw, _gw_name)| gw.wait_for_block_height(block_height)),
    )
    .await?;

    // All unique pairs of gateways.
    // For a list of gateways [A, B, C], this will produce [(A, B), (B, C)].
    // Since the first gateway within each pair initiates the channel open,
    // order within each pair needs to be enforced so that each Lightning node opens
    // 1 channel.
    let gateway_pairs: Vec<(&NamedGateway, &NamedGateway)> =
        gateways.iter().tuple_windows::<(_, _)>().collect();

    info!(target: LOG_DEVIMINT, block_height = %block_height, "devimint current block");
    let sats_per_side = 5_000_000;
    for ((gw_a, gw_a_name), (gw_b, gw_b_name)) in &gateway_pairs {
        info!(target: LOG_DEVIMINT, from=%gw_a_name, to=%gw_b_name, "Opening channel with {sats_per_side} sats on each side...");
        let txid = gw_a
            .open_channel(gw_b, sats_per_side * 2, Some(sats_per_side))
            .await?;

        bitcoind.poll_get_transaction(txid).await?;
    }

    bitcoind.mine_blocks(10).await?;

    let block_height = bitcoind.get_block_count().await? - 1;
    debug!(target: LOG_DEVIMINT, ?block_height, "Syncing gateway lightning nodes to block height...");
    futures::future::try_join_all(
        gateways
            .iter()
            .map(|(gw, _gw_name)| gw.wait_for_block_height(block_height)),
    )
    .await?;

    for ((gw_a, _gw_a_name), (gw_b, _gw_b_name)) in &gateway_pairs {
        let gw_a_node_pubkey = gw_a.lightning_pubkey().await?;
        let gw_b_node_pubkey = gw_b.lightning_pubkey().await?;

        wait_for_ready_channel_on_gateway_with_counterparty(gw_b, gw_a_node_pubkey).await?;
        wait_for_ready_channel_on_gateway_with_counterparty(gw_a, gw_b_node_pubkey).await?;
    }

    info!(target: LOG_DEVIMINT, "open_channels_between_gateways successful");

    Ok(())
}

async fn wait_for_ready_channel_on_gateway_with_counterparty(
    gw: &Gatewayd,
    counterparty_lightning_node_pubkey: bitcoin::secp256k1::PublicKey,
) -> anyhow::Result<()> {
    poll(
        &format!("Wait for {} channel update", gw.gw_name),
        || async {
            let channels = gw
                .list_channels()
                .await
                .context("list channels")
                .map_err(ControlFlow::Break)?;

            if channels
                .iter()
                .any(|channel| channel.remote_pubkey == counterparty_lightning_node_pubkey && channel.is_active)
            {
                return Ok(());
            }

            debug!(target: LOG_DEVIMINT, ?channels, gw = gw.gw_name, "Counterparty channels not found open");
            Err(ControlFlow::Continue(anyhow!("channel not found")))
        },
    )
    .await
}

#[derive(Clone)]
pub enum LightningNode {
    Lnd(Lnd),
    Ldk {
        name: String,
        gw_port: u16,
        ldk_port: u16,
        metrics_port: u16,
    },
}

impl LightningNode {
    pub fn ln_type(&self) -> LightningNodeType {
        match self {
            LightningNode::Lnd(_) => LightningNodeType::Lnd,
            LightningNode::Ldk {
                name: _,
                gw_port: _,
                ldk_port: _,
                metrics_port: _,
            } => LightningNodeType::Ldk,
        }
    }
}

#[derive(Clone)]
pub struct Esplora {
    _process: ProcessHandle,
    _bitcoind: Bitcoind,
}

impl Esplora {
    pub async fn new(process_mgr: &ProcessManager, bitcoind: Bitcoind) -> Result<Self> {
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
        let esplora_monitoring_port = process_mgr.globals.FM_PORT_ESPLORA_MONITORING;
        // spawn esplora
        let cmd = cmd!(
            crate::util::Esplora,
            "--daemon-dir={daemon_dir}",
            "--db-dir={esplora_dir}",
            "--cookie=bitcoin:bitcoin",
            "--network=regtest",
            "--daemon-rpc-addr=127.0.0.1:{btc_rpc_port}",
            "--http-addr=127.0.0.1:{esplora_port}",
            "--monitoring-addr=127.0.0.1:{esplora_monitoring_port}",
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
        // Disable retrying in the client since we're already retrying in the poll below.
        .max_retries(0)
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
    pub esplora: Esplora,
}

pub async fn external_daemons(process_mgr: &ProcessManager) -> Result<ExternalDaemons> {
    let bitcoind = Bitcoind::new(process_mgr, false).await?;
    let esplora = Esplora::new(process_mgr, bitcoind.clone()).await?;
    let start_time = fedimint_core::time::now();
    // make sure the bitcoind wallet is ready
    let _ = bitcoind.wallet_client().await?;
    info!(
        target: LOG_DEVIMINT,
        "starting base daemons took {:?}",
        start_time.elapsed()?
    );
    Ok(ExternalDaemons { bitcoind, esplora })
}
