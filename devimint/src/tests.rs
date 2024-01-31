use std::collections::HashSet;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{env, ffi};

use anyhow::{anyhow, bail, Context, Result};
use bitcoincore_rpc::bitcoin::hashes::hex::ToHex;
use bitcoincore_rpc::bitcoin::Txid;
use bitcoincore_rpc::{bitcoin, RpcApi};
use clap::Subcommand;
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use fedimint_cli::LnInvoiceResponse;
use fedimint_core::encoding::Decodable;
use fedimint_logging::LOG_DEVIMINT;
use ln_gateway::rpc::GatewayInfo;
use semver::VersionReq;
use serde_json::json;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::cli::{cleanup_on_exit, exec_user_command, setup, write_ready_file, CommonArgs};
use crate::federation::{Client, Federation};
use crate::util::{poll, LoadTestTool, ProcessManager};
use crate::{cmd, dev_fed, poll_eq, DevFed, Gatewayd, LightningNode, Lightningd, Lnd};

pub struct Stats {
    pub min: Duration,
    pub avg: Duration,
    pub median: Duration,
    pub p90: Duration,
    pub max: Duration,
    pub sum: Duration,
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "min: {:.1}s", self.min.as_secs_f32())?;
        write!(f, ", avg: {:.1}s", self.avg.as_secs_f32())?;
        write!(f, ", median: {:.1}s", self.median.as_secs_f32())?;
        write!(f, ", p90: {:.1}s", self.p90.as_secs_f32())?;
        write!(f, ", max: {:.1}s", self.max.as_secs_f32())?;
        write!(f, ", sum: {:.1}s", self.sum.as_secs_f32())?;
        Ok(())
    }
}

pub fn stats_for(mut v: Vec<Duration>) -> Stats {
    assert!(!v.is_empty());
    v.sort();
    let n = v.len();
    let max = v.iter().last().unwrap().to_owned();
    let min = v.first().unwrap().to_owned();
    let median = v[n / 2];
    let sum: Duration = v.iter().sum();
    let avg = sum / n as u32;
    let p90 = v[(n as f32 * 0.9) as usize];
    Stats {
        max,
        min,
        sum,
        median,
        avg,
        p90,
    }
}

pub async fn log_binary_versions() -> Result<()> {
    let fedimint_cli_version = cmd!(crate::util::get_fedimint_cli_path(), "--version")
        .out_string()
        .await?;
    info!(?fedimint_cli_version);
    let fedimint_cli_version_hash = cmd!(crate::util::get_fedimint_cli_path(), "version-hash")
        .out_string()
        .await?;
    info!(?fedimint_cli_version_hash);
    let gateway_cli_version = cmd!(crate::util::get_gateway_cli_path(), "--version")
        .out_string()
        .await?;
    info!(?gateway_cli_version);
    let gateway_cli_version_hash = cmd!(crate::util::get_gateway_cli_path(), "version-hash")
        .out_string()
        .await?;
    info!(?gateway_cli_version_hash);
    let fedimintd_version_hash = cmd!(crate::util::FedimintdCmd, "version-hash")
        .out_string()
        .await?;
    info!(?fedimintd_version_hash);
    let gatewayd_version_hash = cmd!(crate::util::Gatewayd, "version-hash")
        .out_string()
        .await?;
    info!(?gatewayd_version_hash);
    Ok(())
}

pub async fn latency_tests(dev_fed: DevFed) -> Result<()> {
    log_binary_versions().await?;
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

    let client = fed.new_joined_client("latency-tests-client").await?;
    client.use_gateway(&gw_cln).await?;
    fed.pegin_client(10_000_000, &client).await?;

    info!("Testing latency of reissue");
    // On AlephBFT session times may lead to high latencies, so we need to run it
    // for enough time to catch up a session end
    let iterations = 30;
    let mut reissues = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let notes = cmd!(client, "spend", "1000000").out_json().await?["notes"]
            .as_str()
            .context("note must be a string")?
            .to_owned();

        let start_time = Instant::now();
        cmd!(client, "reissue", notes).run().await?;
        reissues.push(start_time.elapsed());
    }

    // LN operations take longer, we need less iterations
    let iterations = 20;
    info!("Testing latency of ln send");
    let mut ln_sends = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let add_invoice = lnd
            .lightning_client_lock()
            .await?
            .add_invoice(tonic_lnd::lnrpc::Invoice {
                value_msat: 1_000_000,
                ..Default::default()
            })
            .await?
            .into_inner();

        let invoice = add_invoice.payment_request;
        let payment_hash = add_invoice.r_hash;
        let start_time = Instant::now();
        cmd!(client, "ln-pay", invoice).run().await?;
        let invoice_status = lnd
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
        ln_sends.push(start_time.elapsed());
    }

    info!("Testing latency of ln receive");
    let mut ln_receives = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let invoice = cmd!(
            client,
            "ln-invoice",
            "--amount=1000000msat",
            "--description=incoming-over-lnd-gw"
        )
        .out_json()
        .await?["invoice"]
            .as_str()
            .context("invoice must be string")?
            .to_owned();

        let start_time = Instant::now();
        let payment = lnd
            .lightning_client_lock()
            .await?
            .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
                payment_request: invoice,
                ..Default::default()
            })
            .await?
            .into_inner();
        let payment_status = lnd
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
            .find(|p| p.payment_hash == payment.payment_hash.to_hex())
            .context("payment not in list")?
            .status();
        anyhow::ensure!(payment_status == tonic_lnd::lnrpc::payment::PaymentStatus::Succeeded);
        ln_receives.push(start_time.elapsed());
    }

    info!("Testing latency of internal payments within a federation");
    let mut fm_internal_pay = Vec::with_capacity(iterations);
    let sender = fed.new_joined_client("internal-swap-sender").await?;
    fed.pegin_client(10_000_000, &sender).await?;
    for _ in 0..iterations {
        let recv = cmd!(
            client,
            "ln-invoice",
            "--amount=1000000msat",
            "--description=internal-swap-invoice"
        )
        .out_json()
        .await?;
        let invoice = recv["invoice"]
            .as_str()
            .context("invoice must be string")?
            .to_owned();
        let recv_op = recv["operation_id"]
            .as_str()
            .context("operation id must be string")?
            .to_owned();

        let start_time = Instant::now();
        cmd!(sender, "ln-pay", invoice).run().await?;
        cmd!(client, "await-invoice", recv_op).run().await?;
        fm_internal_pay.push(start_time.elapsed());
    }

    let reissue_stats = stats_for(reissues);
    let ln_sends_stats = stats_for(ln_sends);
    let ln_receives_stats = stats_for(ln_receives);
    let fm_pay_stats = stats_for(fm_internal_pay);

    info!("Testing latency of restore");
    let backup_secret = cmd!(client, "print-secret").out_json().await?["secret"]
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap();
    let restore_client = Client::create("restore").await?;
    let start_time = Instant::now();
    cmd!(
        restore_client,
        "restore",
        "--mnemonic",
        &backup_secret,
        "--invite-code",
        fed.invite_code()?
    )
    .run()
    .await?;
    let restore_time = start_time.elapsed();

    println!(
        "================= RESULTS ==================\n\
              REISSUE: {reissue_stats}\n\
              LN SEND: {ln_sends_stats}\n\
              LN RECV: {ln_receives_stats}\n\
              FM PAY: {fm_pay_stats}\n\
              RESTORE: {restore_time:?}"
    );
    // FIXME: should be smaller
    assert!(reissue_stats.median < Duration::from_secs(4));
    assert!(ln_sends_stats.median < Duration::from_secs(6));
    assert!(ln_receives_stats.median < Duration::from_secs(6));
    assert!(fm_pay_stats.median < Duration::from_secs(6));
    assert!(restore_time < Duration::from_secs(160));
    let factor = 3; // FIXME: should be much smaller
    assert!(reissue_stats.p90 < reissue_stats.median * factor);
    assert!(ln_sends_stats.p90 < ln_sends_stats.median * factor);
    assert!(ln_receives_stats.p90 < ln_receives_stats.median * factor);
    assert!(fm_pay_stats.p90 < fm_pay_stats.median * factor);
    let factor = 3.1f64; // FIXME: should be much smaller
    assert!(reissue_stats.max.as_secs_f64() < reissue_stats.p90.as_secs_f64() * factor);
    assert!(ln_sends_stats.max.as_secs_f64() < ln_sends_stats.p90.as_secs_f64() * factor);
    assert!(ln_receives_stats.max.as_secs_f64() < ln_receives_stats.p90.as_secs_f64() * factor);
    assert!(fm_pay_stats.max.as_secs_f64() < fm_pay_stats.p90.as_secs_f64() * factor);
    Ok(())
}

pub async fn cli_tests(dev_fed: DevFed) -> Result<()> {
    log_binary_versions().await?;
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

    let client = fed.new_joined_client("cli-tests-client").await?;
    client.use_gateway(&gw_cln).await?;

    cmd!(
        client,
        "dev",
        "config-decrypt",
        "--in-file={data_dir}/fedimintd-0/private.encrypt",
        "--out-file={data_dir}/fedimintd-0/config-plaintext.json"
    )
    .env("FM_PASSWORD", "pass")
    .run()
    .await?;

    cmd!(
        client,
        "dev",
        "config-encrypt",
        "--in-file={data_dir}/fedimintd-0/config-plaintext.json",
        "--out-file={data_dir}/fedimintd-0/config-2"
    )
    .env("FM_PASSWORD", "pass-foo")
    .run()
    .await?;

    cmd!(
        client,
        "dev",
        "config-decrypt",
        "--in-file={data_dir}/fedimintd-0/config-2",
        "--out-file={data_dir}/fedimintd-0/config-plaintext-2.json"
    )
    .env("FM_PASSWORD", "pass-foo")
    .run()
    .await?;

    let plaintext_one =
        fs::read_to_string(format!("{data_dir}/fedimintd-0/config-plaintext.json")).await?;
    let plaintext_two =
        fs::read_to_string(format!("{data_dir}/fedimintd-0/config-plaintext-2.json")).await?;
    anyhow::ensure!(
        plaintext_one == plaintext_two,
        "config-decrypt/encrypt failed"
    );

    fed.pegin_gateway(10_000_000, &gw_cln).await?;

    let fed_id = fed.federation_id().await;
    let invite = fed.invite_code()?;
    let invite_code = cmd!(client, "dev", "decode-invite-code", invite.clone())
        .out_json()
        .await?;
    anyhow::ensure!(
        cmd!(
            client,
            "dev",
            "encode-invite-code",
            format!("--url={}", invite_code["url"].as_str().unwrap()),
            "--federation_id={fed_id}",
            "--peer=0"
        )
        .out_json()
        .await?["invite_code"]
            .as_str()
            .unwrap()
            == invite,
        "failed to decode and encode the client invite code",
    );

    // Test that LND and CLN can still send directly to each other

    // LND can pay CLN directly
    info!("Testing LND can pay CLN directly");
    let invoice = cln
        .request(cln_rpc::model::requests::InvoiceRequest {
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(1_200_000)),
            description: "test".to_string(),
            label: "test2".to_string(),
            expiry: Some(60),
            fallbacks: None,
            preimage: None,
            cltv: None,
            deschashonly: None,
        })
        .await?
        .bolt11;
    lnd.lightning_client_lock()
        .await?
        .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
            payment_request: invoice.clone(),
            ..Default::default()
        })
        .await?
        .into_inner();
    let invoice_status = cln
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

    // CLN can pay LND directly
    info!("Testing CLN can pay LND directly");
    let add_invoice = lnd
        .lightning_client_lock()
        .await?
        .add_invoice(tonic_lnd::lnrpc::Invoice {
            value_msat: 1_000_000,
            ..Default::default()
        })
        .await?
        .into_inner();
    let invoice = add_invoice.payment_request;
    let payment_hash = add_invoice.r_hash;
    cln.request(cln_rpc::model::requests::PayRequest {
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

    // fedimintd introduced wpkh for single guardian federations in v0.3.0 (9e35bdb)
    // The code path is backwards-compatible, however this test will fail if we
    // check against earlier fedimintd versions.
    let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
    if VersionReq::parse(">=0.3.0-alpha")?.matches(&fedimintd_version) {
        // # Test the correct descriptor is used
        let config = cmd!(client, "config").out_json().await?;
        let guardian_count = config["global"]["api_endpoints"].as_object().unwrap().len();
        let descriptor = config["modules"]["2"]["peg_in_descriptor"]
            .as_str()
            .unwrap()
            .to_owned();

        info!("Testing generated descriptor for {guardian_count} guardian federation");
        if guardian_count == 1 {
            assert!(descriptor.contains("wpkh("));
        } else {
            assert!(descriptor.contains("wsh(sortedmulti("));
        }
    }

    // # Client tests
    info!("Testing Client");
    // ## reissue e-cash
    info!("Testing reissuing e-cash");
    const CLIENT_START_AMOUNT: u64 = 5_000_000_000;
    const CLIENT_SPEND_AMOUNT: u64 = 1_100_000;

    let initial_client_balance = client.balance().await?;
    assert_eq!(initial_client_balance, 0);

    fed.pegin_client(CLIENT_START_AMOUNT / 1000, &client)
        .await?;

    // Check log contains deposit
    let operation = cmd!(client, "list-operations")
        .out_json()
        .await?
        .get("operations")
        .expect("Output didn't contain operation log")
        .as_array()
        .unwrap()
        .first()
        .unwrap()
        .to_owned();
    assert_eq!(operation["operation_kind"].as_str().unwrap(), "wallet");
    assert!(operation["outcome"]["Claimed"].as_object().is_some());

    info!("Testing backup&restore");
    // TODO: make sure there are no in-progress operations involved
    // This test can't tolerate "spend", but not "reissue"d coins currently,
    // and there's a no clean way to do `reissue` on `spend` output ATM
    // so just putting it here for time being.
    cli_tests_backup_and_restore(&fed, &client).await?;

    // # Spend from client
    info!("Testing spending from client");
    let notes = cmd!(client, "spend", CLIENT_SPEND_AMOUNT)
        .out_json()
        .await?
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap()
        .to_owned();

    let client_post_spend_balance = client.balance().await?;
    assert_eq!(
        client_post_spend_balance,
        CLIENT_START_AMOUNT - CLIENT_SPEND_AMOUNT
    );

    // Test we can reissue our own notes
    cmd!(client, "reissue", notes).out_json().await?;

    let client_post_spend_balance = client.balance().await?;
    assert_eq!(client_post_spend_balance, CLIENT_START_AMOUNT);

    let reissue_amount: u64 = 409600;

    // Ensure that client can reissue after spending
    info!("Testing reissuing e-cash after spending");
    let _notes = cmd!(client, "spend", CLIENT_SPEND_AMOUNT)
        .out_json()
        .await?
        .as_object()
        .unwrap()
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap();

    let reissue_notes = cmd!(client, "spend", reissue_amount).out_json().await?["notes"]
        .as_str()
        .map(|s| s.to_owned())
        .unwrap();
    let client_reissue_amt = cmd!(client, "reissue", reissue_notes)
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    assert_eq!(client_reissue_amt, reissue_amount);

    // Ensure that client can reissue via module commands
    info!("Testing reissuing e-cash via module commands");
    let reissue_notes = cmd!(client, "spend", reissue_amount).out_json().await?["notes"]
        .as_str()
        .map(|s| s.to_owned())
        .unwrap();
    let client_reissue_amt = cmd!(
        client,
        "module",
        "--module",
        "mint",
        "reissue",
        reissue_notes
    )
    .out_json()
    .await?
    .as_u64()
    .unwrap();
    assert_eq!(client_reissue_amt, reissue_amount);

    // Before doing a normal payment, let's start with a HOLD invoice and only
    // finish this payment at the end
    info!("Testing fedimint-cli pays LND HOLD invoice via CLN gateway");
    let (hold_invoice_preimage, hold_invoice_hash, hold_invoice_operation_id) =
        start_hold_invoice_payment(&client, &gw_cln, &lnd).await?;

    // OUTGOING: fedimint-cli pays LND via CLN gateway
    info!("Testing fedimint-cli pays LND via CLN gateway");
    client.use_gateway(&gw_cln).await?;

    let initial_client_balance = client.balance().await?;
    let initial_cln_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    let add_invoice = lnd
        .lightning_client_lock()
        .await?
        .add_invoice(tonic_lnd::lnrpc::Invoice {
            value_msat: 1_200_000,
            ..Default::default()
        })
        .await?
        .into_inner();
    let invoice = add_invoice.payment_request;
    let payment_hash = add_invoice.r_hash;
    cmd!(client, "ln-pay", invoice).run().await?;

    let invoice_status = lnd
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

    // Assert balances changed by 1_200_000 msat (amount sent) + 0 msat (fee)
    let final_cln_outgoing_client_balance = client.balance().await?;
    let final_cln_outgoing_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();

    let expected_diff = 1_200_000;
    anyhow::ensure!(
        initial_client_balance - final_cln_outgoing_client_balance == expected_diff,
        "Client balance changed by {} on CLN outgoing payment, expected {expected_diff}",
        initial_client_balance - final_cln_outgoing_client_balance
    );
    anyhow::ensure!(
        final_cln_outgoing_gateway_balance - initial_cln_gateway_balance == expected_diff,
        "CLN Gateway balance changed by {} on CLN outgoing payment, expected {expected_diff}",
        final_cln_outgoing_gateway_balance - initial_cln_gateway_balance
    );

    let ln_response_val = cmd!(
        client,
        "ln-invoice",
        "--amount=1100000msat",
        "--description='incoming-over-cln-gw'"
    )
    .out_json()
    .await?;
    let ln_invoice_response: LnInvoiceResponse = serde_json::from_value(ln_response_val)?;
    let invoice = ln_invoice_response.invoice;
    let payment = lnd
        .lightning_client_lock()
        .await?
        .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
            payment_request: invoice.clone(),
            ..Default::default()
        })
        .await?
        .into_inner();
    let payment_status = lnd
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
        .find(|p| p.payment_hash == payment.payment_hash.to_hex())
        .context("payment not in list")?
        .status();
    anyhow::ensure!(payment_status == tonic_lnd::lnrpc::payment::PaymentStatus::Succeeded);

    // Receive the ecash notes
    info!("Testing receiving e-cash notes");
    let operation_id = ln_invoice_response.operation_id;
    cmd!(client, "await-invoice", operation_id).run().await?;

    // Assert balances changed by 1100000 msat
    let final_cln_incoming_client_balance = client.balance().await?;
    let final_cln_incoming_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_cln_incoming_client_balance - final_cln_outgoing_client_balance == 1100000,
        "Client balance changed by {} on CLN incoming payment, expected 1100000",
        final_cln_incoming_client_balance - final_cln_outgoing_client_balance
    );
    anyhow::ensure!(
        final_cln_outgoing_gateway_balance - final_cln_incoming_gateway_balance == 1100000,
        "CLN Gateway balance changed by {} on CLN incoming payment, expected 1100000",
        final_cln_outgoing_gateway_balance - final_cln_incoming_gateway_balance
    );

    // LND gateway tests
    info!("Testing LND gateway");
    client.use_gateway(&gw_lnd).await?;

    // OUTGOING: fedimint-cli pays CLN via LND gateaway
    info!("Testing outgoing payment from client to CLN via LND gateway");
    let initial_lnd_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    let invoice = cln
        .request(cln_rpc::model::requests::InvoiceRequest {
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(2_000_000)),
            description: "lnd-gw-to-cln".to_string(),
            label: "test-client".to_string(),
            expiry: Some(60),
            fallbacks: None,
            preimage: None,
            cltv: None,
            deschashonly: None,
        })
        .await?
        .bolt11;
    tokio::try_join!(cln.await_block_processing(), lnd.await_block_processing())?;
    cmd!(client, "ln-pay", invoice.clone()).run().await?;
    let fed_id = fed.federation_id().await;

    let invoice_status = cln
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

    // Assert balances changed by 2_000_000 msat (amount sent) + 0 msat (fee)
    let final_lnd_outgoing_client_balance = client.balance().await?;
    let final_lnd_outgoing_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_cln_incoming_client_balance - final_lnd_outgoing_client_balance == 2_000_000,
        "Client balance changed by {} on LND outgoing payment, expected 2_000_000",
        final_cln_incoming_client_balance - final_lnd_outgoing_client_balance
    );
    anyhow::ensure!(
        final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance == 2_000_000,
        "LND Gateway balance changed by {} on LND outgoing payment, expected 2_000_000",
        final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance
    );

    // INCOMING: fedimint-cli receives from CLN via LND gateway
    info!("Testing incoming payment from CLN to client via LND gateway");
    let ln_response_val = cmd!(
        client,
        "ln-invoice",
        "--amount=1300000msat",
        "--description='incoming-over-lnd-gw'"
    )
    .out_json()
    .await?;
    let ln_invoice_response: LnInvoiceResponse = serde_json::from_value(ln_response_val)?;
    let invoice = ln_invoice_response.invoice;
    let invoice_status = cln
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
        })
        .await?
        .status;
    anyhow::ensure!(matches!(
        invoice_status,
        cln_rpc::model::responses::PayStatus::COMPLETE
    ));

    // Receive the ecash notes
    info!("Testing receiving ecash notes");
    let operation_id = ln_invoice_response.operation_id;
    cmd!(client, "await-invoice", operation_id).run().await?;

    // Assert balances changed by 1_300_000 msat
    let final_lnd_incoming_client_balance = client.balance().await?;
    let final_lnd_incoming_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_lnd_incoming_client_balance - final_lnd_outgoing_client_balance == 1_300_000,
        "Client balance changed by {} on LND incoming payment, expected 1_300_000",
        final_lnd_incoming_client_balance - final_lnd_outgoing_client_balance
    );
    anyhow::ensure!(
        final_lnd_outgoing_gateway_balance - final_lnd_incoming_gateway_balance == 1_300_000,
        "LND Gateway balance changed by {} on LND incoming payment, expected 1_300_000",
        final_lnd_outgoing_gateway_balance - final_lnd_incoming_gateway_balance
    );

    info!("Will finish the payment of the LND HOLD invoice via CLN gateway");
    finish_hold_invoice_payment(
        &client,
        hold_invoice_operation_id,
        &lnd,
        hold_invoice_hash,
        hold_invoice_preimage,
    )
    .await?;

    // TODO: test cancel/timeout

    // # Wallet tests
    // ## Deposit
    info!("Testing client deposit");
    let initial_walletng_balance = client.balance().await?;

    fed.pegin_client(100_000, &client).await?; // deposit in sats

    let post_deposit_walletng_balance = client.balance().await?;

    assert_eq!(
        post_deposit_walletng_balance,
        initial_walletng_balance + 100_000_000 // deposit in msats
    );

    // ## Withdraw
    info!("Testing client withdraw");

    let initial_walletng_balance = client.balance().await?;

    let address = bitcoind.get_new_address().await?;
    let withdraw_res = cmd!(
        client,
        "withdraw",
        "--address",
        &address,
        "--amount",
        "50000 sat"
    )
    .out_json()
    .await?;

    let txid: Txid = withdraw_res["txid"].as_str().unwrap().parse().unwrap();
    let fees_sat = withdraw_res["fees_sat"].as_u64().unwrap();

    let tx_hex = poll("Waiting for transaction in mempool", None, || async {
        // TODO: distinguish errors from not found
        bitcoind
            .get_raw_transaction(&txid)
            .await
            .context("getrawtransaction")
            .map_err(ControlFlow::Continue)
    })
    .await
    .expect("cannot fail, gets stuck");

    let tx = bitcoin::Transaction::consensus_decode_hex(&tx_hex, &Default::default()).unwrap();
    let address = bitcoin::Address::from_str(&address).unwrap();
    assert!(tx
        .output
        .iter()
        .any(|o| o.script_pubkey == address.script_pubkey() && o.value == 50000));

    let post_withdraw_walletng_balance = client.balance().await?;
    let expected_wallet_balance = initial_walletng_balance - 50_000_000 - (fees_sat * 1000);

    assert_eq!(post_withdraw_walletng_balance, expected_wallet_balance);

    Ok(())
}

pub async fn start_hold_invoice_payment(
    client: &Client,
    gw_cln: &Gatewayd,
    lnd: &Lnd,
) -> anyhow::Result<([u8; 32], cln_rpc::primitives::Sha256, String)> {
    client.use_gateway(gw_cln).await?;
    let preimage = rand::random::<[u8; 32]>();
    let hash = {
        use fedimint_core::BitcoinHash;
        let mut engine = bitcoin::hashes::sha256::Hash::engine();
        bitcoin::hashes::HashEngine::input(&mut engine, &preimage);
        bitcoin::hashes::sha256::Hash::from_engine(engine)
    };
    let payment_request = lnd
        .invoices_client_lock()
        .await?
        .add_hold_invoice(tonic_lnd::invoicesrpc::AddHoldInvoiceRequest {
            value_msat: 1000,
            hash: hash.to_vec(),
            ..Default::default()
        })
        .await?
        .into_inner()
        .payment_request;
    let operation_id = cmd!(client, "ln-pay", payment_request, "--finish-in-background")
        .out_json()
        .await?["operation_id"]
        .as_str()
        .context("missing operation id")?
        .to_owned();
    Ok((preimage, hash, operation_id))
}

pub async fn finish_hold_invoice_payment(
    client: &Client,
    hold_invoice_operation_id: String,
    lnd: &Lnd,
    hold_invoice_hash: cln_rpc::primitives::Sha256,
    hold_invoice_preimage: [u8; 32],
) -> anyhow::Result<()> {
    let mut hold_invoice_subscription = lnd
        .invoices_client_lock()
        .await?
        .subscribe_single_invoice(tonic_lnd::invoicesrpc::SubscribeSingleInvoiceRequest {
            r_hash: hold_invoice_hash.to_vec(),
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
                } else {
                    debug!("hold invoice payment state: {:?}", invoice.state());
                }
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
    lnd.invoices_client_lock()
        .await?
        .settle_invoice(tonic_lnd::invoicesrpc::SettleInvoiceMsg {
            preimage: hold_invoice_preimage.to_vec(),
        })
        .await?;
    let received_preimage = cmd!(client, "await-ln-pay", hold_invoice_operation_id)
        .out_json()
        .await?["preimage"]
        .as_str()
        .context("missing preimage")?
        .to_owned();
    assert_eq!(received_preimage, hold_invoice_preimage.to_hex());
    Ok(())
}

pub async fn cli_load_test_tool_test(dev_fed: DevFed) -> Result<()> {
    log_binary_versions().await?;
    let data_dir = env::var("FM_DATA_DIR")?;
    let load_test_temp = PathBuf::from(data_dir).join("load-test-temp");
    dev_fed
        .fed
        .pegin_client(10_000, dev_fed.fed.internal_client())
        .await?;
    let invite_code = dev_fed.fed.invite_code()?;
    run_standard_load_test(&load_test_temp, &invite_code).await?;
    run_ln_circular_load_test(&load_test_temp, &invite_code).await?;
    Ok(())
}

pub async fn run_standard_load_test(
    load_test_temp: &Path,
    invite_code: &str,
) -> anyhow::Result<()> {
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "load-test",
        "--notes-per-user",
        "1",
        "--generate-invoice-with",
        "cln-lightning-cli",
        "--invite-code",
        invite_code
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("2 reissue_notes"),
        "reissued different number notes than expected"
    );
    anyhow::ensure!(
        output.contains("1 gateway_pay_invoice"),
        "paid different number of invoices than expected"
    );
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "load-test",
        "--notes-per-user",
        "1",
        "--generate-invoice-with",
        "ln-cli"
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("compared to previous"),
        "did not compare to previous run"
    );
    anyhow::ensure!(
        output.contains("2 reissue_notes"),
        "reissued different number notes than expected"
    );
    anyhow::ensure!(
        output.contains("1 gateway_pay_invoice"),
        "paid different number of invoices than expected"
    );
    Ok(())
}

pub async fn run_ln_circular_load_test(
    load_test_temp: &Path,
    invite_code: &str,
) -> anyhow::Result<()> {
    info!("Testing ln-circular-load-test with 'two-gateways' strategy");
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "ln-circular-load-test",
        "--strategy",
        "two-gateways",
        "--test-duration-secs",
        "2",
        "--invite-code",
        invite_code
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("gateway_create_invoice"),
        "missing invoice creation"
    );
    anyhow::ensure!(
        output.contains("gateway_pay_invoice_success"),
        "missing invoice payment"
    );
    anyhow::ensure!(
        output.contains("gateway_payment_received_success"),
        "missing received payment"
    );

    info!("Testing ln-circular-load-test with 'partner-ping-pong' strategy");
    // Note invite code isn't required because we already have an archive dir
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "ln-circular-load-test",
        "--strategy",
        "partner-ping-pong",
        "--test-duration-secs",
        "2",
        "--invite-code",
        invite_code
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("gateway_create_invoice"),
        "missing invoice creation"
    );
    anyhow::ensure!(
        output.contains("gateway_payment_received_success"),
        "missing received payment"
    );

    info!("Testing ln-circular-load-test with 'self-payment' strategy");
    // Note invite code isn't required because we already have an archive dir
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "ln-circular-load-test",
        "--strategy",
        "self-payment",
        "--test-duration-secs",
        "2",
        "--invite-code",
        invite_code
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("gateway_create_invoice"),
        "missing invoice creation"
    );
    anyhow::ensure!(
        output.contains("gateway_payment_received_success"),
        "missing received payment"
    );
    Ok(())
}

pub async fn cli_tests_backup_and_restore(
    fed: &Federation,
    reference_client: &Client,
) -> Result<()> {
    // fedimint-cli updated the interface for `restore` in v0.3.0 (3746d51)
    // The code path is backwards-compatible, however we need to handle the two
    // separate interfaces to test backwards-compatibility with old clients.
    let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
    let secret = cmd!(reference_client, "print-secret").out_json().await?["secret"]
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap();

    let pre_notes = cmd!(reference_client, "info").out_json().await?;

    let pre_balance = pre_notes["total_amount_msat"].as_u64().unwrap();

    debug!(%pre_notes, pre_balance, "State before backup");

    // we need to have some funds
    // TODO: right now we rely on previous tests to leave some balance
    assert!(0 < pre_balance);

    // without existing backup
    // TODO: Change this test and make them exercise more scenarios.
    // Currently (and probably indefinitely) we can support only one
    // restoration per client state (datadir), as it only makes sense to do
    // once (at the very beginning) and we used a fixed operation id for it.
    // Testing restore in different setups would require multiple clients,
    // which is a larger refactor.
    {
        let post_balance = if VersionReq::parse(">=0.3.0-alpha")?.matches(&fedimint_cli_version) {
            let client = Client::create("restore-without-backup").await?;
            let _ = cmd!(
                client,
                "restore",
                "--mnemonic",
                &secret,
                "--invite-code",
                fed.invite_code()?
            )
            .out_json()
            .await?;

            // `wait-complete` was introduced in v0.3.0 (90f3082)
            let _ = cmd!(client, "dev", "wait-complete").out_json().await?;
            let post_notes = cmd!(client, "info").out_json().await?;
            let post_balance = post_notes["total_amount_msat"].as_u64().unwrap();
            debug!(%post_notes, post_balance, "State after backup");

            post_balance
        } else {
            let client = reference_client
                .new_forked("restore-without-backup")
                .await?;
            let _ = cmd!(client, "wipe", "--force",).out_json().await?;

            assert_eq!(
                0,
                cmd!(client, "info").out_json().await?["total_amount_msat"]
                    .as_u64()
                    .unwrap()
            );

            let post_balance = cmd!(client, "restore", &secret,)
                .out_json()
                .await?
                .as_u64()
                .unwrap();
            let post_notes = cmd!(client, "info").out_json().await?;
            debug!(%post_notes, post_balance, "State after backup");

            post_balance
        };
        assert_eq!(pre_balance, post_balance);
    }

    // with a backup
    {
        let post_balance = if VersionReq::parse(">=0.3.0-alpha")?.matches(&fedimint_cli_version) {
            let _ = cmd!(reference_client, "backup",).out_json().await?;
            let client = Client::create("restore-with-backup").await?;

            let _ = cmd!(
                client,
                "restore",
                "--mnemonic",
                &secret,
                "--invite-code",
                fed.invite_code()?
            )
            .out_json()
            .await?;

            let _ = cmd!(client, "dev", "wait-complete").out_json().await?;
            let post_notes = cmd!(client, "info").out_json().await?;
            let post_balance = post_notes["total_amount_msat"].as_u64().unwrap();
            debug!(%post_notes, post_balance, "State after backup");

            post_balance
        } else {
            let client = reference_client.new_forked("restore-with-backup").await?;
            let _ = cmd!(client, "backup",).out_json().await?;
            let _ = cmd!(client, "wipe", "--force",).out_json().await?;
            assert_eq!(
                0,
                cmd!(client, "info").out_json().await?["total_amount_msat"]
                    .as_u64()
                    .unwrap()
            );
            let _ = cmd!(client, "restore", &secret,).out_json().await?;
            let post_notes = cmd!(client, "info").out_json().await?;
            let post_balance = post_notes["total_amount_msat"].as_u64().unwrap();
            debug!(%post_notes, post_balance, "State after backup");

            post_balance
        };
        assert_eq!(pre_balance, post_balance);
    }

    Ok(())
}

pub async fn lightning_gw_reconnect_test(
    dev_fed: DevFed,
    process_mgr: &ProcessManager,
) -> Result<()> {
    log_binary_versions().await?;
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

    let client = fed
        .new_joined_client("lightning-gw-reconnect-test-client")
        .await?;
    client.use_gateway(&gw_cln).await?;

    info!("Pegging-in both gateways");
    fed.pegin_gateway(99_999, &gw_cln).await?;
    fed.pegin_gateway(99_999, &gw_lnd).await?;

    // Drop other references to CLN and LND so that the test can kill them
    drop(cln);
    drop(lnd);

    let mut gateways = vec![gw_cln, gw_lnd];

    tracing::info!("Stopping all lightning nodes");
    for gw in &mut gateways {
        // Verify that the gateway can query the lightning node for the pubkey and alias
        let mut info_cmd = cmd!(gw, "info");
        assert!(info_cmd.run().await.is_ok());

        // Verify that after stopping the lightning node, info no longer returns the
        // node public key since the lightning node is unreachable.
        gw.stop_lightning_node().await?;
        let lightning_info = info_cmd.out_json().await?;
        let gateway_info: GatewayInfo = serde_json::from_value(lightning_info)?;
        assert!(gateway_info.lightning_pub_key.is_none());
    }

    // Restart both lightning nodes
    tracing::info!("Restarting both lightning nodes...");
    let new_cln = Lightningd::new(process_mgr, bitcoind.clone()).await?;
    let new_lnd = Lnd::new(process_mgr, bitcoind.clone()).await?;
    gateways[0].set_lightning_node(LightningNode::Cln(new_cln.clone()));
    gateways[1].set_lightning_node(LightningNode::Lnd(new_lnd.clone()));

    tracing::info!("Retrying info...");
    const MAX_RETRIES: usize = 10;
    const RETRY_INTERVAL: Duration = Duration::from_secs(1);
    for gw in gateways {
        for i in 0..MAX_RETRIES {
            match do_try_create_and_pay_invoice(&gw, &client, &new_cln, &new_lnd).await {
                Ok(_) => break,
                Err(e) => {
                    if i == MAX_RETRIES - 1 {
                        return Err(e);
                    } else {
                        tracing::debug!(
                            "Pay invoice for gateway {} failed with {e:?}, retrying in {} seconds (try {}/{MAX_RETRIES})",
                            gw.ln
                                .as_ref()
                                .map(|ln| ln.name().to_string())
                                .unwrap_or_default(),
                            RETRY_INTERVAL.as_secs(),
                            i + 1,
                        );
                        fedimint_core::task::sleep(RETRY_INTERVAL).await;
                    }
                }
            }
        }
    }

    info!(target: LOG_DEVIMINT, "lightning_reconnect_test: success");
    Ok(())
}

pub async fn gw_reboot_test(dev_fed: DevFed, process_mgr: &ProcessManager) -> Result<()> {
    log_binary_versions().await?;
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

    let client = fed.new_joined_client("gw-reboot-test-client").await?;
    client.use_gateway(&gw_cln).await?;
    fed.pegin_client(10_000, &client).await?;

    // Query current gateway infos
    let mut cln_cmd = cmd!(gw_cln, "info");
    let mut lnd_cmd = cmd!(gw_lnd, "info");
    let (cln_value, lnd_value) = tokio::try_join!(cln_cmd.out_json(), lnd_cmd.out_json())?;

    // Drop references to cln and lnd gateways so the test can kill them
    drop(gw_cln);
    drop(gw_lnd);

    // Verify that making a payment while the gateways are down does not result in
    // funds being stuck
    info!("Making payment while gateway is down");
    let initial_client_balance = client.balance().await?;
    let add_invoice = lnd
        .lightning_client_lock()
        .await?
        .add_invoice(tonic_lnd::lnrpc::Invoice {
            value_msat: 3000,
            ..Default::default()
        })
        .await?
        .into_inner();
    let invoice = add_invoice.payment_request;
    cmd!(client, "ln-pay", invoice)
        .run()
        .await
        .expect_err("Expected ln-pay to return error because the gateway is not online");
    let new_client_balance = client.balance().await?;
    anyhow::ensure!(initial_client_balance == new_client_balance);

    // Reboot gateways with the same Lightning node instances
    info!("Rebooting gateways...");
    let (new_gw_cln, new_gw_lnd) = tokio::try_join!(
        Gatewayd::new(process_mgr, LightningNode::Cln(cln.clone())),
        Gatewayd::new(process_mgr, LightningNode::Lnd(lnd.clone()))
    )?;

    let cln_info: GatewayInfo = serde_json::from_value(cln_value)?;
    poll(
        "Waiting for CLN Gateway Running state after reboot",
        10,
        || async {
            let mut new_cln_cmd = cmd!(new_gw_cln, "info");
            let cln_value = new_cln_cmd.out_json().await.map_err(ControlFlow::Continue)?;
            let reboot_info: GatewayInfo = serde_json::from_value(cln_value).context("json invalid").map_err(ControlFlow::Break)?;

            if reboot_info.gateway_state == "Running" {
                info!(target: LOG_DEVIMINT, "CLN Gateway restarted, with auto-rejoin to federation");
                // Assert that the gateway info is the same as before the reboot
                assert_eq!(cln_info, reboot_info);
                return Ok(());
            }
            Err(ControlFlow::Continue(anyhow!("gateway not running")))
        },
    )
    .await?;

    let lnd_info: GatewayInfo = serde_json::from_value(lnd_value)?;
    poll(
        "Waiting for LND Gateway Running state after reboot",
        10,
        || async {
            let mut new_lnd_cmd = cmd!(new_gw_lnd, "info");
            let lnd_value = new_lnd_cmd.out_json().await.map_err(ControlFlow::Continue)?;
            let reboot_info: GatewayInfo = serde_json::from_value(lnd_value).context("json invalid").map_err(ControlFlow::Break)?;

            if reboot_info.gateway_state == "Running" {
                info!(target: LOG_DEVIMINT, "LND Gateway restarted, with auto-rejoin to federation");
                // Assert that the gateway info is the same as before the reboot
                assert_eq!(lnd_info, reboot_info);
                return Ok(());
            }
            Err(ControlFlow::Continue(anyhow!("gateway not running")))
        },
    )
    .await?;

    info!(LOG_DEVIMINT, "gateway_reboot_test: success");
    Ok(())
}

pub async fn do_try_create_and_pay_invoice(
    gw: &Gatewayd,
    client: &Client,
    new_cln: &Lightningd,
    new_lnd: &Lnd,
) -> anyhow::Result<()> {
    // Verify that after the lightning node has restarted, the gateway
    // automatically reconnects and can query the lightning node
    // info again.
    poll(
        "Waiting for info to succeed after restart",
        None,
        || async {
            let mut info_cmd = cmd!(gw, "info");
            let lightning_info = info_cmd.out_json().await.map_err(ControlFlow::Continue)?;
            let gateway_info: GatewayInfo = serde_json::from_value(lightning_info)
                .context("invalid json")
                .map_err(ControlFlow::Break)?;
            poll_eq!(gateway_info.lightning_pub_key.is_some(), true)
        },
    )
    .await?;

    client.use_gateway(gw).await?;
    tracing::info!("Creating invoice....");
    let ln_response_val = cmd!(
        client,
        "ln-invoice",
        "--amount=1000msat",
        "--description='incoming-over-cln-gw'"
    )
    .out_json()
    .await?;
    let ln_invoice_response: LnInvoiceResponse = serde_json::from_value(ln_response_val)?;
    let invoice = ln_invoice_response.invoice;

    match gw.ln.as_ref() {
        Some(LightningNode::Cln(_cln)) => {
            // Pay the invoice using LND
            let payment = new_lnd
                .lightning_client_lock()
                .await?
                .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
                    payment_request: invoice.clone(),
                    ..Default::default()
                })
                .await?
                .into_inner();

            let payment_status = new_lnd
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
                .find(|p| p.payment_hash == payment.payment_hash.to_hex())
                .context("payment not in list")?
                .status();
            anyhow::ensure!(payment_status == tonic_lnd::lnrpc::payment::PaymentStatus::Succeeded);
        }
        Some(LightningNode::Lnd(_lnd)) => {
            // Pay the invoice using CLN
            let invoice_status = new_cln
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
                })
                .await?
                .status;
            anyhow::ensure!(matches!(
                invoice_status,
                cln_rpc::model::responses::PayStatus::COMPLETE
            ));
        }
        None => {
            panic!("Lightning node did not come back up correctly");
        }
    }
    Ok(())
}

pub async fn reconnect_test(dev_fed: DevFed, process_mgr: &ProcessManager) -> Result<()> {
    log_binary_versions().await?;
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
    fed.terminate_server(0).await?;
    fed.mine_then_wait_blocks_sync(100).await?;

    fed.start_server(process_mgr, 0).await?;
    fed.mine_then_wait_blocks_sync(100).await?;
    fed.await_all_peers().await?;
    info!(target: LOG_DEVIMINT, "Server 0 successfully rejoined!");
    fed.mine_then_wait_blocks_sync(100).await?;

    // now test what happens if consensus needs to be restarted
    fed.terminate_server(1).await?;
    fed.mine_then_wait_blocks_sync(100).await?;
    fed.terminate_server(2).await?;
    fed.terminate_server(3).await?;

    fed.start_server(process_mgr, 1).await?;
    fed.start_server(process_mgr, 2).await?;
    fed.start_server(process_mgr, 3).await?;

    poll("federation back online", None, || async {
        fed.await_all_peers().await.map_err(ControlFlow::Continue)?;
        Ok(())
    })
    .await?;

    info!(target: LOG_DEVIMINT, "fm success: reconnect-test");
    Ok(())
}

pub async fn recoverytool_test(dev_fed: DevFed) -> Result<()> {
    log_binary_versions().await?;
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
    let data_dir = env::var("FM_DATA_DIR")?;
    let client = fed.new_joined_client("recoverytool-test-client").await?;

    let mut fed_utxos_sats = HashSet::from([12_345_000, 23_456_000, 34_567_000]);
    for sats in &fed_utxos_sats {
        fed.pegin_client(*sats, &client).await?;
    }

    // Initiate a withdrawal to verify the recoverytool recognizes change outputs
    let withdrawal_address = bitcoind.get_new_address().await?;
    let withdraw_res = cmd!(
        client,
        "withdraw",
        "--address",
        &withdrawal_address,
        "--amount",
        "5000 sat"
    )
    .out_json()
    .await?;

    let fees_sat = withdraw_res["fees_sat"]
        .as_u64()
        .expect("withdrawal should contain fees");
    let txid: Txid = withdraw_res["txid"]
        .as_str()
        .expect("withdrawal should contain txid string")
        .parse()
        .expect("txid should be parsable");
    let tx_hex = poll("Waiting for transaction in mempool", None, || async {
        bitcoind
            .get_raw_transaction(&txid)
            .await
            .context("getrawtransaction")
            .map_err(ControlFlow::Continue)
    })
    .await
    .expect("withdrawal tx failed to reach mempool");

    let tx = bitcoin::Transaction::consensus_decode_hex(&tx_hex, &Default::default())?;
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);

    let withdrawal_address = bitcoin::Address::from_str(&withdrawal_address)?;
    let change_output = tx
        .output
        .iter()
        .find(|o| o.to_owned().script_pubkey != withdrawal_address.script_pubkey())
        .expect("withdrawal must have change output");
    assert!(fed_utxos_sats.insert(change_output.value));

    // Remove the utxo consumed from the withdrawal tx
    let total_output_sats = tx.output.iter().map(|o| o.value).sum::<u64>();
    let input_sats = total_output_sats + fees_sat;
    assert!(fed_utxos_sats.remove(&input_sats));

    let total_fed_sats = fed_utxos_sats.iter().sum::<u64>();
    fed.finalize_mempool_tx().await?;

    let now = fedimint_core::time::now();
    info!("Recovering using utxos method");
    let output = cmd!(
        crate::util::Recoverytool,
        "--readonly",
        "--cfg",
        "{data_dir}/fedimintd-0",
        "utxos",
        "--db",
        "{data_dir}/fedimintd-0/database"
    )
    .env("FM_PASSWORD", "pass")
    .out_json()
    .await?;
    let outputs = output.as_array().context("expected an array")?;
    assert_eq!(outputs.len(), fed_utxos_sats.len());

    assert_eq!(
        outputs
            .iter()
            .map(|o| o["amount_sat"].as_u64().unwrap())
            .collect::<HashSet<_>>(),
        fed_utxos_sats
    );
    let utxos_descriptors = outputs
        .iter()
        .map(|o| o["descriptor"].as_str().unwrap())
        .collect::<HashSet<_>>();

    let descriptors_json = [serde_json::value::to_raw_value(&serde_json::Value::Array(
        utxos_descriptors
            .iter()
            .map(|d| {
                let object = json!({
                    "desc": d,
                    "timestamp": 0,
                });
                object
            })
            .collect::<Vec<_>>(),
    ))?];
    info!("Getting wallet balances before import");
    let balances_before = bitcoind.client().get_balances()?;
    info!("Importing descriptors into bitcoin wallet");
    let request = bitcoind
        .client()
        .get_jsonrpc_client()
        .build_request("importdescriptors", &descriptors_json);
    let response = bitcoind
        .client()
        .get_jsonrpc_client()
        .send_request(request)?;
    response.check_error()?;
    info!("Getting wallet balances after import");
    let balances_after = bitcoind.client().get_balances()?;
    let diff = balances_after.mine.immature + balances_after.mine.trusted
        - balances_before.mine.immature
        - balances_before.mine.trusted;
    // Funds from descriptors should match the the fed's utxos
    assert_eq!(diff.to_sat(), total_fed_sats);
    info!("Recovering using epochs method");
    let outputs = loop {
        let output = cmd!(
            crate::util::Recoverytool,
            "--readonly",
            "--cfg",
            "{data_dir}/fedimintd-0",
            "epochs",
            "--db",
            "{data_dir}/fedimintd-0/database"
        )
        .env("FM_PASSWORD", "pass")
        .out_json()
        .await?;
        let outputs = output.as_array().context("expected an array")?;
        if outputs.len() >= fed_utxos_sats.len() {
            break outputs.clone();
        } else if now.elapsed()? > Duration::from_secs(180) {
            // 3 minutes should be enough to finish one or two sessions
            bail!("recoverytool epochs method timed out");
        } else {
            fedimint_core::task::sleep(Duration::from_secs(1)).await
        }
    };
    let epochs_descriptors = outputs
        .iter()
        .map(|o| o["descriptor"].as_str().unwrap())
        .collect::<HashSet<_>>();
    // Epochs method includes descriptors from spent outputs, so we only need to
    // verify the epochs method includes all available utxos
    for utxo_descriptor in utxos_descriptors.iter() {
        assert!(epochs_descriptors.contains(*utxo_descriptor))
    }
    Ok(())
}

#[derive(Subcommand)]
pub enum TestCmd {
    /// `devfed` then checks the average latency of reissuing ecash, LN receive,
    /// and LN send
    LatencyTests,
    /// `devfed` then kills and restarts most of the Guardian nodes in a 4 node
    /// fedimint
    ReconnectTest,
    /// `devfed` then tests a bunch of the fedimint-cli commands
    CliTests,
    /// `devfed` then calls binary `fedimint-load-test-tool`. See
    /// `LoadTestArgs`.
    LoadTestToolTest,
    /// `devfed` then pegin CLN & LND nodes and gateways. Kill the LN nodes,
    /// restart them, rejjoin fedimint and test payments still work
    LightningReconnectTest,
    /// `devfed` then reboot gateway daemon for both CLN and LND. Test
    /// afterward.
    GatewayRebootTest,
    /// `devfed` then tests if the recovery tool is able to do a basic recovery
    RecoverytoolTests,
    /// `devfed` then spawns faucet for wasm tests
    WasmTestSetup {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
}

pub async fn handle_command(cmd: TestCmd, common_args: CommonArgs) -> Result<()> {
    match cmd {
        TestCmd::WasmTestSetup { exec } => {
            let (process_mgr, task_group) = setup(common_args).await?;
            let main = {
                let task_group = task_group.clone();
                async move {
                    let dev_fed = dev_fed(&process_mgr).await?;
                    let (_, _, faucet) = tokio::try_join!(
                        dev_fed.fed.pegin_gateway(20_000, &dev_fed.gw_cln),
                        dev_fed.fed.pegin_gateway(20_000, &dev_fed.gw_lnd),
                        async {
                            let faucet = process_mgr
                                .spawn_daemon("faucet", cmd!(crate::util::Faucet))
                                .await?;

                            poll("waiting for faucet startup", None, || async {
                                TcpStream::connect(format!(
                                    "127.0.0.1:{}",
                                    process_mgr.globals.FM_PORT_FAUCET
                                ))
                                .await
                                .context("connect to faucet")
                                .map_err(ControlFlow::Continue)
                            })
                            .await?;
                            Ok(faucet)
                        },
                    )?;
                    let daemons = write_ready_file(&process_mgr.globals, Ok(dev_fed)).await?;
                    if let Some(exec) = exec {
                        exec_user_command(exec).await?;
                        task_group.shutdown();
                    }
                    Ok::<_, anyhow::Error>((daemons, faucet))
                }
            };
            cleanup_on_exit(main, task_group).await?;
        }
        TestCmd::LatencyTests => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            latency_tests(dev_fed).await?;
        }
        TestCmd::ReconnectTest => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            reconnect_test(dev_fed, &process_mgr).await?;
        }
        TestCmd::CliTests => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            cli_tests(dev_fed).await?;
        }
        TestCmd::LoadTestToolTest => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            cli_load_test_tool_test(dev_fed).await?;
        }
        TestCmd::LightningReconnectTest => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            lightning_gw_reconnect_test(dev_fed, &process_mgr).await?;
        }
        TestCmd::GatewayRebootTest => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            gw_reboot_test(dev_fed, &process_mgr).await?;
        }
        TestCmd::RecoverytoolTests => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            recoverytool_test(dev_fed).await?;
        }
    }
    Ok(())
}
