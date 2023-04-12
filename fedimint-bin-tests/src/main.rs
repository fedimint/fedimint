use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bitcoin::hashes::hex::ToHex;
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::{bitcoin, RpcApi};
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
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

mod util;
use util::*;

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
        let bin_dir = env::var("FM_BIN_DIR")?;

        let cmd = cmd!(
            "lightningd",
            "--dev-fast-gossip",
            "--dev-bitcoind-poll=1",
            "--lightning-dir={cln_dir}",
            "--plugin={bin_dir}/gateway-cln-extension"
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
        Ok(Self {
            _bitcoind: bitcoind,
            client: Arc::new(Mutex::new(client)),
            _process: process,
        })
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
        let bin_dir = env::var("FM_BIN_DIR")?;
        let ln_name = ln.name();
        let test_dir = env::var("FM_TEST_DIR")?;
        let gateway_env = match ln {
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
                cmd!("{bin_dir}/gatewayd", ln_name).envs(gateway_env),
            )
            .await?;

        Ok(Self {
            ln,
            _process: process,
        })
    }

    pub async fn cmd(&self) -> Command {
        let bin_dir = env::var("FM_BIN_DIR").expect("FM_BIN_DIR not found");
        match &self.ln {
            ClnOrLnd::Cln(_) => {
                cmd!("{bin_dir}/gateway-cli", "--rpcpassword=theresnosecondbest")
            }
            ClnOrLnd::Lnd(_) => {
                cmd!(
                    "{bin_dir}/gateway-cli",
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

mod federation;

async fn latency_tests(dev_fed: DevFed) -> Result<()> {
    #[allow(unused_variables)]
    let DevFed {
        bitcoind,
        cln,
        lnd,
        fed,
        gw_cln,
        gw_lnd,
        electrs,
        esplora,
    } = dev_fed;

    fed.pegin(10_000_000).await?;
    let iterations = 10;
    let start_time = Instant::now();
    for _ in 0..iterations {
        let notes = cmd!(fed, "spend", "50000").out_json().await?["note"]
            .as_str()
            .context("note must be a string")?
            .to_owned();

        cmd!(fed, "reissue", notes).run().await?;
        cmd!(fed, "fetch").run().await?;
    }
    let reissue_time = start_time.elapsed().as_secs_f64() / (iterations as f64);

    let start_time = Instant::now();
    for _ in 0..iterations {
        let add_invoice = lnd
            .client_lock()
            .await?
            .add_invoice(tonic_lnd::lnrpc::Invoice {
                value_msat: 100_000,
                ..Default::default()
            })
            .await?
            .into_inner();

        let invoice = add_invoice.payment_request;
        let payment_hash = add_invoice.r_hash;

        cmd!(fed, "ln-pay", invoice).run().await?;
        let invoice_status = lnd
            .client_lock()
            .await?
            .lookup_invoice(tonic_lnd::lnrpc::PaymentHash {
                r_hash: payment_hash,
                ..Default::default()
            })
            .await?
            .into_inner()
            .state();

        anyhow::ensure!(invoice_status == tonic_lnd::lnrpc::invoice::InvoiceState::Settled);
    }
    let ln_send_time = start_time.elapsed().as_secs_f64() / (iterations as f64);

    let start_time = Instant::now();
    for _ in 0..iterations {
        let invoice = cmd!(
            fed,
            "ln-invoice",
            "--amount=100000msat",
            "--description=incoming-over-lnd-gw"
        )
        .out_json()
        .await?["invoice"]
            .as_str()
            .context("invoice must be string")?
            .to_owned();

        let payment = lnd
            .client_lock()
            .await?
            .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
                payment_request: invoice,
                ..Default::default()
            })
            .await?
            .into_inner();
        let payment_status = lnd
            .client_lock()
            .await?
            .list_payments(tonic_lnd::lnrpc::ListPaymentsRequest {
                include_incomplete: true,
                ..Default::default()
            })
            .await?
            .into_inner()
            .payments
            .into_iter()
            .find(|p| p.payment_hash == payment.payment_hash.to_hex())
            .context("payment not in list")?
            .status();
        anyhow::ensure!(payment_status == tonic_lnd::lnrpc::payment::PaymentStatus::Succeeded);
    }
    let ln_recv_time = start_time.elapsed().as_secs_f64() / (iterations as f64);
    println!(
        "================= RESULTS ==================\n\
              AVG REISSUE TIME: {reissue_time:.3}\n\
              AVG LN SEND TIME: {ln_send_time:.3}\n\
              AVG LN RECV TIME: {ln_recv_time:.3}"
    );
    Ok(())
}

async fn cli_tests(dev_fed: DevFed) -> Result<()> {
    let bin_dir = env::var("FM_BIN_DIR")?;
    let data_dir = env::var("FM_DATA_DIR")?;

    #[allow(unused_variables)]
    let DevFed {
        bitcoind,
        cln,
        lnd,
        fed,
        gw_cln,
        gw_lnd,
        electrs,
        esplora,
    } = dev_fed;

    cmd!(
        "{bin_dir}/distributedgen",
        "config-decrypt",
        "--in-file={data_dir}/server-0/private.encrypt",
        "--out-file={data_dir}/server-0/config-plaintext.json"
    )
    .env("FM_PASSWORD", "pass0");

    cmd!(
        "{bin_dir}/distributedgen",
        "config-encrypt",
        "--in-file={data_dir}/server-0/config-plaintext.json",
        "--out-file={data_dir}/server-0/config-2"
    )
    .env("FM_PASSWORD", "pass-foo");

    cmd!(
        "{bin_dir}/distributedgen",
        "config-decrypt",
        "--in-file={data_dir}/server-0/config-2",
        "--out-file={data_dir}/server-0/config-plaintext-2.json"
    )
    .env("FM_PASSWORD", "pass-foo");

    let plaintext_one =
        fs::read_to_string(format!("{data_dir}/server-0/config-plaintext.json")).await?;
    let plaintext_two =
        fs::read_to_string(format!("{data_dir}/server-0/config-plaintext-2.json")).await?;
    anyhow::ensure!(
        plaintext_one == plaintext_two,
        "config-decrypt/encrypt failed"
    );

    fed.pegin(10_000).await;
    fed.pegin_gateway(99_999, &gw_cln).await;

    let connect_string = fs::read_to_string(format!("{}/client-connect", data_dir)).await?;
    fs::remove_file(format!("{}/client.json", data_dir));
    cmd!(fed, "join-federation", connect_string.clone());

    let fed_id = fed.federation_id().await;
    let connect_info = cmd!(fed, "decode-connect-info", connect_string.clone())
        .out_json()
        .await?;
    anyhow::ensure!(
        cmd!(
            fed,
            "encode-connect-info",
            format!("--url={}", connect_info["url"]),
            format!("--download-token={}", connect_info["download_token"]),
            "--id={fed_id}"
        )
        .out_json()
        .await?["connect_info"]
            .to_string()
            == connect_string,
        "failed to decode and encode the client connection info string",
    );

    // reissue
    let notes = cmd!(fed, "spend", "42000msat").out_json().await?["note"].clone();
    assert_eq!(
        cmd!(fed, "info").out_json().await?["total_amount"]
            .as_u64()
            .unwrap(),
        9_958_000
    );
    cmd!(fed, "validate", notes.clone());
    cmd!(fed, "reissue", notes);
    cmd!(fed, "fetch");

    // peg out
    let pegout_addr = bitcoind.client().get_new_address(None, None)?;
    cmd!(
        fed,
        "peg-out",
        format!("--address={}", pegout_addr.clone()),
        "--amount=500sat"
    );
    let amount = Amount::from_btc("0.00000500".parse::<f64>()?)?;
    poll("btc_amount_receive", || async {
        let received_by_addr = bitcoind
            .client()
            .get_received_by_address(&pegout_addr.clone(), Some(0))?;
        Ok(received_by_addr != amount)
    });
    bitcoind.mine_blocks(10);
    let received = bitcoind
        .client()
        .get_received_by_address(&pegout_addr, Some(0))?;
    anyhow::ensure!(
        received != amount,
        "Peg-out address received {}, expected 0.00000500",
        received
    );

    // lightning tests
    tokio::try_join!(cln.await_block_processing(), lnd.await_block_processing())?;

    // CLN gateway tests
    fed.use_gateway(&gw_cln);

    // OUTGOING: fedimint-cli pays LND via CLN gateway
    let initial_client_balance = cmd!(fed, "info").out_json().await?["total_amount"]
        .as_f64()
        .unwrap();
    let initial_gateway_balance = cmd!(
        gw_cln,
        "balance",
        format!("--federation-id={}", fed_id.clone())
    )
    .out_json()
    .await?["balance_msat"]
        .as_f64()
        .unwrap();
    let add_invoice = lnd
        .client_lock()
        .await?
        .add_invoice(tonic_lnd::lnrpc::Invoice {
            value_msat: 100_000,
            ..Default::default()
        })
        .await?
        .into_inner();
    let invoice = add_invoice.payment_request;
    let payment_hash = add_invoice.r_hash;
    cmd!(fed, "ln-pay", invoice);

    let invoice_status = lnd
        .client_lock()
        .await?
        .lookup_invoice(tonic_lnd::lnrpc::PaymentHash {
            r_hash: payment_hash,
            ..Default::default()
        })
        .await?
        .into_inner()
        .state();
    anyhow::ensure!(invoice_status == tonic_lnd::lnrpc::invoice::InvoiceState::Settled);

    // Assert balances changed by 100000 msat (amount sent) + 1000 msat (fee)
    let final_client_balance = cmd!(fed, "info").out_json().await?["total_amount"]
        .as_f64()
        .unwrap();
    let final_gateway_balance = cmd!(
        gw_cln,
        "balance",
        format!("--federation-id={}", fed_id.clone())
    )
    .out_json()
    .await?["balance_msat"]
        .as_f64()
        .unwrap();
    anyhow::ensure!(
        initial_client_balance - final_client_balance != 101_000 as f64,
        "Client balance changed by {}, expected 101000",
        initial_client_balance - final_client_balance
    );
    anyhow::ensure!(
        final_gateway_balance - initial_gateway_balance != 101_000 as f64,
        "Gateway balance changed by {}, expected 101000",
        final_gateway_balance - initial_gateway_balance
    );

    // INCOMING: fedimint-cli receives from LND via CLN gateway
    let invoice = cmd!(
        fed,
        "ln-invoice",
        "--amount=100000msat",
        "--description='incoming-over-lnd-gw'"
    )
    .out_json()
    .await?["invoice"]
        .as_str()
        .context("invoice must be string")?
        .to_owned();
    let payment = lnd
        .client_lock()
        .await?
        .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
            payment_request: invoice.clone(),
            ..Default::default()
        })
        .await?
        .into_inner();
    let payment_status = lnd
        .client_lock()
        .await?
        .list_payments(tonic_lnd::lnrpc::ListPaymentsRequest {
            include_incomplete: true,
            ..Default::default()
        })
        .await?
        .into_inner()
        .payments
        .into_iter()
        .find(|p| p.payment_hash == payment.payment_hash.to_hex())
        .context("payment not in list")?
        .status();
    anyhow::ensure!(payment_status == tonic_lnd::lnrpc::payment::PaymentStatus::Succeeded);

    // LND gateway tests
    fed.use_gateway(&gw_lnd);

    // OUTGOING: fedimint-cli pays CLN via LND gateaway
    let initial_client_balance = cmd!(fed, "info").out_json().await?["total_amount"]
        .as_f64()
        .unwrap();
    let initial_gateway_balance = cmd!(
        gw_cln,
        "balance",
        format!("--federation-id={}", fed_id.clone())
    )
    .out_json()
    .await?["balance_msat"]
        .as_f64()
        .unwrap();
    let invoice = cln
        .request(cln_rpc::model::InvoiceRequest {
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(100_000)),
            description: "lnd-gw-to-cln".to_string(),
            label: "test".to_string(),
            expiry: Some(1),
            fallbacks: None,
            preimage: None,
            exposeprivatechannels: None,
            cltv: None,
            deschashonly: None,
        })
        .await?
        .bolt11;
    tokio::try_join!(cln.await_block_processing(), lnd.await_block_processing())?;
    cmd!(fed, "ln-pay", invoice.clone());
    let fed_id = fed.federation_id().await;

    let invoice_status = cln
        .request(cln_rpc::model::WaitanyinvoiceRequest {
            lastpay_index: None,
            timeout: None,
        })
        .await?
        .status;
    anyhow::ensure!(matches!(
        invoice_status,
        cln_rpc::model::WaitanyinvoiceStatus::PAID
    ));

    // Assert balances changed by 100000 msat (amount sent) + 1000 msat (fee)
    let final_client_balance = cmd!(fed, "info").out_json().await?["total_amount"]
        .as_f64()
        .unwrap();
    let final_gateway_balance = cmd!(
        gw_cln,
        "balance",
        format!("--federation-id={}", fed_id.clone())
    )
    .out_json()
    .await?["balance_msat"]
        .as_f64()
        .unwrap();
    anyhow::ensure!(
        initial_client_balance - final_client_balance != 101_000 as f64,
        "Client balance changed by {}, expected 101000",
        initial_client_balance - final_client_balance
    );
    anyhow::ensure!(
        final_gateway_balance - initial_gateway_balance != 101_000 as f64,
        "Gateway balance changed by {}, expected 101000",
        final_gateway_balance - initial_gateway_balance
    );

    // INCOMING: fedimint-cli receives from CLN via LND gateway
    let invoice = cmd!(
        fed,
        "ln-invoice",
        "--amount=100000msat",
        "--description='integration test'"
    )
    .out_json()
    .await?["invoice"]
        .clone();
    let invoice_status = cln
        .request(cln_rpc::model::PayRequest {
            bolt11: invoice.to_string(),
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
        })
        .await?
        .status;
    anyhow::ensure!(matches!(
        invoice_status,
        cln_rpc::model::PayStatus::COMPLETE
    ));

    // Test that LND and CLN can still send directly to each other

    // LND can pay CLN directly
    let invoice = cln
        .request(cln_rpc::model::InvoiceRequest {
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(42_000)),
            description: "test".to_string(),
            label: "test".to_string(),
            expiry: Some(1),
            fallbacks: None,
            preimage: None,
            exposeprivatechannels: None,
            cltv: None,
            deschashonly: None,
        })
        .await?
        .bolt11;
    let payment = lnd
        .client_lock()
        .await?
        .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
            payment_request: invoice.clone(),
            ..Default::default()
        })
        .await?
        .into_inner();
    let invoice_status = cln
        .request(cln_rpc::model::WaitanyinvoiceRequest {
            lastpay_index: None,
            timeout: None,
        })
        .await?
        .status;
    anyhow::ensure!(matches!(
        invoice_status,
        cln_rpc::model::WaitanyinvoiceStatus::PAID
    ));

    // CLN can pay LND directly
    let add_invoice = lnd
        .client_lock()
        .await?
        .add_invoice(tonic_lnd::lnrpc::Invoice {
            value_msat: 100_000,
            ..Default::default()
        })
        .await?
        .into_inner();
    let invoice = add_invoice.payment_request;
    let payment_hash = add_invoice.r_hash;
    cln.request(cln_rpc::model::PayRequest {
        bolt11: invoice.to_string(),
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
    })
    .await?;
    let invoice_status = lnd
        .client_lock()
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

async fn reconnect_test(dev_fed: DevFed, process_mgr: &ProcessManager) -> Result<()> {
    #[allow(unused_variables)]
    let DevFed {
        bitcoind,
        cln,
        lnd,
        mut fed,
        gw_cln,
        gw_lnd,
        electrs,
        esplora,
    } = dev_fed;

    bitcoind.mine_blocks(110).await?;
    fed.await_block_sync().await?;
    fed.await_all_peers().await?;

    // test a peer missing out on epochs and needing to rejoin
    fed.kill_server(0).await?;
    // FIXME increase this number once we can avoid processing epoch messages too
    // far in the future
    fed.generate_epochs(1).await?;

    fed.start_server(process_mgr, 0).await?;
    // FIXME increase this number once we can avoid processing epoch messages too
    // far in the future
    fed.generate_epochs(1).await?;
    fed.await_all_peers().await?;
    info!("Server 0 successfully rejoined!");
    bitcoind.mine_blocks(100).await?;

    // now test what happens if consensus needs to be restarted
    fed.kill_server(1).await?;
    bitcoind.mine_blocks(100).await?;
    fed.await_block_sync().await?;
    fed.kill_server(2).await?;
    fed.kill_server(3).await?;

    fed.start_server(process_mgr, 1).await?;
    fed.start_server(process_mgr, 2).await?;
    fed.start_server(process_mgr, 3).await?;
    fed.await_all_peers().await?;
    info!("fm success: reconnect-test");
    Ok(())
}

struct DevFed {
    bitcoind: Bitcoind,
    cln: Lightningd,
    lnd: Lnd,
    fed: Federation,
    gw_cln: Gatewayd,
    gw_lnd: Gatewayd,
    electrs: Electrs,
    esplora: Esplora,
}

async fn dev_fed(task_group: &TaskGroup, process_mgr: &ProcessManager) -> Result<DevFed> {
    let bitcoind = Bitcoind::new(process_mgr).await?;
    let (cln, lnd, electrs, esplora) = tokio::try_join!(
        Lightningd::new(process_mgr, bitcoind.clone()),
        Lnd::new(process_mgr, bitcoind.clone()),
        Electrs::new(process_mgr, bitcoind.clone()),
        Esplora::new(process_mgr, bitcoind.clone()),
    )?;
    info!("lightning and bitcoind started");
    run_dkg(task_group, 4).await?;
    info!("dkg done");
    open_channel(&bitcoind, &cln, &lnd).await?;

    info!("channel open");
    let fed = Federation::new(process_mgr, bitcoind.clone(), 0..4).await?;
    info!("federation started");
    let gw_cln = Gatewayd::new(process_mgr, ClnOrLnd::Cln(cln.clone())).await?;
    let gw_lnd = Gatewayd::new(process_mgr, ClnOrLnd::Lnd(lnd.clone())).await?;
    info!("gateway started");
    tokio::try_join!(gw_cln.connect_fed(&fed), gw_lnd.connect_fed(&fed))?;
    fed.await_gateways_registered().await?;
    info!("gateways registered");
    fed.use_gateway(&gw_cln).await?;
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

async fn tmuxinator(process_mgr: &ProcessManager, task_group: &TaskGroup) -> Result<()> {
    let ready_file = env::var("FM_READY_FILE")?;
    match dev_fed(task_group, process_mgr).await {
        Ok(_dev_fed) => {
            fs::write(ready_file, "READY").await?;
            task_group.make_handle().make_shutdown_rx().await.await?;
            Ok(())
        }
        Err(e) => {
            fs::write(ready_file, "ERROR").await?;
            Err(e)
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

use clap::{Parser, Subcommand};

#[derive(Subcommand)]
enum Cmd {
    Tmuxinator,
    LatencyTests,
    ReconnectTest,
    CliTests,
}

#[derive(Parser)]
#[command(version)]
struct Args {
    #[clap(subcommand)]
    command: Cmd,
}

#[tokio::main]
async fn main() -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    let process_mgr = ProcessManager::new();
    let task_group = TaskGroup::new();
    task_group.install_kill_handler();
    let args = Args::parse();
    match args.command {
        Cmd::Tmuxinator => tmuxinator(&process_mgr, &task_group).await?,
        Cmd::LatencyTests => {
            let dev_fed = dev_fed(&task_group, &process_mgr).await?;
            latency_tests(dev_fed).await?;
        }
        Cmd::ReconnectTest => {
            let dev_fed = dev_fed(&task_group, &process_mgr).await?;
            reconnect_test(dev_fed, &process_mgr).await?;
        }
        Cmd::CliTests => {
            let dev_fed = dev_fed(&task_group, &process_mgr).await?;
            cli_tests(dev_fed).await?;
        }
    }
    Ok(())
}
