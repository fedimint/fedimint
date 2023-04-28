use std::collections::BTreeSet;
use std::env;
use std::time::Instant;

use anyhow::{Context, Result};
use bitcoincore_rpc::bitcoin::hashes::hex::ToHex;
use bitcoincore_rpc::bitcoin::Amount as BitcoinRpcAmount;
use bitcoincore_rpc::RpcApi;
use clap::{Parser, Subcommand};
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use devimint::federation::{fedimint_env, Fedimintd};
use devimint::util::{poll, ProcessManager};
use devimint::{cmd, dev_fed, external_daemons, Bitcoind, DevFed};
use fedimint_core::task::TaskGroup;
use tokio::fs;
use tokio::net::TcpStream;
use tracing::info;

pub async fn latency_tests(dev_fed: DevFed) -> Result<()> {
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
        "distributedgen",
        "config-decrypt",
        "--in-file={data_dir}/server-0/private.encrypt",
        "--out-file={data_dir}/server-0/config-plaintext.json"
    )
    .env("FM_PASSWORD", "pass0")
    .run()
    .await?;

    cmd!(
        "distributedgen",
        "config-encrypt",
        "--in-file={data_dir}/server-0/config-plaintext.json",
        "--out-file={data_dir}/server-0/config-2"
    )
    .env("FM_PASSWORD", "pass-foo")
    .run()
    .await?;

    cmd!(
        "distributedgen",
        "config-decrypt",
        "--in-file={data_dir}/server-0/config-2",
        "--out-file={data_dir}/server-0/config-plaintext-2.json"
    )
    .env("FM_PASSWORD", "pass-foo")
    .run()
    .await?;

    // Test load last epoch with admin client
    let epoch_json = cmd!(fed, "last-epoch")
        .env("FM_SALT_PATH", format!("{data_dir}/server-0/private.salt"))
        .env("FM_PASSWORD", "pass0")
        .env("FM_OUR_ID", "0")
        .out_json()
        .await?;
    let epoch_hex = epoch_json["hex_outcome"].as_str().unwrap();
    let _force_epoch = cmd!(fed, "force-epoch", epoch_hex)
        .env("FM_SALT_PATH", format!("{data_dir}/server-0/private.salt"))
        .env("FM_PASSWORD", "pass0")
        .env("FM_OUR_ID", "0")
        .out_json()
        .await?;

    let plaintext_one =
        fs::read_to_string(format!("{data_dir}/server-0/config-plaintext.json")).await?;
    let plaintext_two =
        fs::read_to_string(format!("{data_dir}/server-0/config-plaintext-2.json")).await?;
    anyhow::ensure!(
        plaintext_one == plaintext_two,
        "config-decrypt/encrypt failed"
    );

    fed.pegin(10_000).await?;
    fed.pegin_gateway(99_999, &gw_cln).await?;

    let connect_string = fs::read_to_string(format!("{data_dir}/client-connect")).await?;
    fs::remove_file(format!("{data_dir}/client.json")).await?;
    cmd!(fed, "join-federation", connect_string.clone())
        .run()
        .await?;

    let fed_id = fed.federation_id().await;
    let connect_info = cmd!(fed, "decode-connect-info", connect_string.clone())
        .out_json()
        .await?;
    anyhow::ensure!(
        cmd!(
            fed,
            "encode-connect-info",
            format!("--url={}", connect_info["url"].as_str().unwrap()),
            format!(
                "--download-token={}",
                connect_info["download_token"].as_str().unwrap()
            ),
            "--id={fed_id}"
        )
        .out_json()
        .await?["connect_info"]
            .as_str()
            .unwrap()
            == connect_string,
        "failed to decode and encode the client connection info string",
    );

    // reissue
    let notes = cmd!(fed, "spend", "42000msat").out_json().await?["note"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        cmd!(fed, "info").out_json().await?["total_amount"]
            .as_u64()
            .unwrap(),
        9_958_000
    );
    cmd!(fed, "validate", notes.clone()).run().await?;
    cmd!(fed, "reissue", notes).run().await?;
    cmd!(fed, "fetch").run().await?;

    // peg out
    let pegout_addr = bitcoind.client().get_new_address(None, None)?;
    cmd!(fed, "peg-out", "--address={pegout_addr}", "--amount=500sat")
        .run()
        .await?;
    let amount = BitcoinRpcAmount::from_btc("0.00000500".parse::<f64>()?)?;
    poll("btc_amount_receive", || async {
        let received_by_addr = bitcoind
            .client()
            .get_received_by_address(&pegout_addr.clone(), Some(0))?;
        Ok(received_by_addr != amount)
    })
    .await?;
    bitcoind.mine_blocks(10).await?;
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
    fed.use_gateway(&gw_cln).await?;

    // OUTGOING: fedimint-cli pays LND via CLN gateway
    let initial_client_balance = cmd!(fed, "info").out_json().await?["total_amount"]
        .as_u64()
        .unwrap();
    let initial_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?["balance_msat"]
        .as_u64()
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

    // Assert balances changed by 100000 msat (amount sent) + 1000 msat (fee)
    let final_client_balance = cmd!(fed, "info").out_json().await?["total_amount"]
        .as_u64()
        .unwrap();
    let final_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?["balance_msat"]
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        initial_client_balance - final_client_balance == 101_000,
        "Client balance changed by {}, expected 101000",
        initial_client_balance - final_client_balance
    );
    anyhow::ensure!(
        final_gateway_balance - initial_gateway_balance == 101_000,
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
    fed.use_gateway(&gw_lnd).await?;

    // OUTGOING: fedimint-cli pays CLN via LND gateaway
    let initial_client_balance = cmd!(fed, "info").out_json().await?["total_amount"]
        .as_u64()
        .unwrap();
    let initial_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?["balance_msat"]
        .as_u64()
        .unwrap();
    let invoice = cln
        .request(cln_rpc::model::InvoiceRequest {
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(100_000)),
            description: "lnd-gw-to-cln".to_string(),
            label: "test".to_string(),
            expiry: Some(60),
            fallbacks: None,
            preimage: None,
            exposeprivatechannels: None,
            cltv: None,
            deschashonly: None,
        })
        .await?
        .bolt11;
    tokio::try_join!(cln.await_block_processing(), lnd.await_block_processing())?;
    cmd!(fed, "ln-pay", invoice.clone()).run().await?;
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
        .as_u64()
        .unwrap();
    let final_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?["balance_msat"]
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        initial_client_balance - final_client_balance == 101_000,
        "Client balance changed by {}, expected 101000",
        initial_client_balance - final_client_balance
    );
    anyhow::ensure!(
        final_gateway_balance - initial_gateway_balance == 101_000,
        "Gateway balance changed by {}, expected 101000",
        final_gateway_balance - initial_gateway_balance
    );

    // INCOMING: fedimint-cli receives from CLN via LND gateway
    let invoice = cmd!(
        fed,
        "ln-invoice",
        "--amount=100000msat",
        "--description=integration test"
    )
    .out_json()
    .await?["invoice"]
        .as_str()
        .unwrap()
        .to_owned();
    let invoice_status = cln
        .request(cln_rpc::model::PayRequest {
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
            label: "test2".to_string(),
            expiry: Some(60),
            fallbacks: None,
            preimage: None,
            exposeprivatechannels: None,
            cltv: None,
            deschashonly: None,
        })
        .await?
        .bolt11;
    lnd.client_lock()
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

    // # Clinet-NG tests
    // ## reissue e-cash

    const CLIENT_NG_REISSE_AMOUNT: u64 = 420;
    const CLIENT_NG_SPEND_AMOUNT: u64 = 42;

    let initial_clientng_balance = cmd!(fed, "ng", "info").out_json().await?["total_msat"]
        .as_u64()
        .unwrap();
    assert_eq!(initial_clientng_balance, 0);

    let reissue_notes = cmd!(fed, "spend", CLIENT_NG_REISSE_AMOUNT)
        .out_json()
        .await?["note"]
        .as_str()
        .map(|s| s.to_owned())
        .unwrap();
    let client_ng_reissue_amt = cmd!(fed, "ng", "reissue", reissue_notes)
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    assert_eq!(client_ng_reissue_amt, CLIENT_NG_REISSE_AMOUNT);

    let initial_clientng_balance = cmd!(fed, "ng", "info").out_json().await?["total_msat"]
        .as_u64()
        .unwrap();
    assert_eq!(initial_clientng_balance, CLIENT_NG_REISSE_AMOUNT);

    // # Spend from client ng
    let reissue_notes_denominations = cmd!(fed, "ng", "spend", CLIENT_NG_SPEND_AMOUNT)
        .out_json()
        .await?
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.to_owned())
        .collect::<BTreeSet<_>>();

    let expected_denominations = vec!["2", "8", "32"]
        .into_iter()
        .map(|s| s.to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(reissue_notes_denominations, expected_denominations);

    let clientng_post_spend_balance = cmd!(fed, "ng", "info").out_json().await?["total_msat"]
        .as_u64()
        .unwrap();
    assert_eq!(
        clientng_post_spend_balance,
        CLIENT_NG_REISSE_AMOUNT - CLIENT_NG_SPEND_AMOUNT
    );

    // TODO: test cancel/timeout

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
    fed.generate_epochs(10).await?;

    fed.start_server(process_mgr, 0).await?;
    fed.generate_epochs(10).await?;
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

#[derive(Subcommand)]
enum Cmd {
    ExternalDaemons,
    Tmuxinator,
    RunUi,
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

async fn write_ready_file<T>(result: Result<T>) -> Result<T> {
    let ready_file = env::var("FM_READY_FILE")?;
    match result {
        Ok(_) => fs::write(ready_file, "READY").await?,
        Err(_) => fs::write(ready_file, "ERROR").await?,
    }
    result
}

async fn run_ui(process_mgr: &ProcessManager, task_group: &TaskGroup) -> Result<()> {
    let bitcoind = Bitcoind::new(process_mgr).await?;
    let mut fedimints = Vec::new();
    for id in 0..2 {
        fedimints.push(Fedimintd::new(process_mgr, bitcoind.clone(), id).await?);
    }
    for id in 0..2 {
        let ui_addr = &fedimint_env(id)?["FM_LISTEN_UI"];
        poll("waiting for ui startup", || async {
            Ok(TcpStream::connect(ui_addr).await.is_ok())
        })
        .await?;
        info!("Started UI on http://{ui_addr}");
    }
    task_group.make_handle().make_shutdown_rx().await.await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    let process_mgr = ProcessManager::new();
    let task_group = TaskGroup::new();
    task_group.install_kill_handler();
    let args = Args::parse();
    match args.command {
        Cmd::ExternalDaemons => {
            let _daemons = write_ready_file(external_daemons(&process_mgr).await).await?;
            task_group.make_handle().make_shutdown_rx().await.await?;
        }
        Cmd::Tmuxinator => {
            let _daemons = write_ready_file(dev_fed(&task_group, &process_mgr).await).await?;
            task_group.make_handle().make_shutdown_rx().await.await?;
        }
        Cmd::RunUi => run_ui(&process_mgr, &task_group).await?,
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
