use std::collections::HashSet;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, ffi};

use anyhow::{anyhow, bail, Context, Result};
use bitcoincore_rpc::bitcoin::hashes::hex::ToHex;
use bitcoincore_rpc::bitcoin::Txid;
use bitcoincore_rpc::{bitcoin, RpcApi};
use clap::{Parser, Subcommand};
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use devimint::federation::{Federation, Fedimintd};
use devimint::util::{poll, ProcessManager};
use devimint::{
    cmd, dev_fed, external_daemons, poll_eq, vars, DevFed, ExternalDaemons, Gatewayd,
    LightningNode, Lightningd, Lnd,
};
use fedimint_cli::LnInvoiceResponse;
use fedimint_core::task::{timeout, TaskGroup};
use fedimint_core::util::write_overwrite_async;
use fedimint_logging::LOG_DEVIMINT;
use ln_gateway::rpc::GatewayInfo;
use serde_json::json;
use tokio::fs;
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

struct Stats {
    min: Duration,
    avg: Duration,
    median: Duration,
    p90: Duration,
    max: Duration,
    sum: Duration,
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

fn stats_for(mut v: Vec<Duration>) -> Stats {
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
    info!("Testing latency of reissue");
    // On AlephBFT session times may lead to high latencies, so we need to run it
    // for enough time to catch up a session end
    let iterations = 30;
    let mut reissues = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let notes = cmd!(fed, "spend", "50000").out_json().await?["notes"]
            .as_str()
            .context("note must be a string")?
            .to_owned();

        let start_time = Instant::now();
        cmd!(fed, "reissue", notes).run().await?;
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
                value_msat: 100_000,
                ..Default::default()
            })
            .await?
            .into_inner();

        let invoice = add_invoice.payment_request;
        let payment_hash = add_invoice.r_hash;
        let start_time = Instant::now();
        cmd!(fed, "ln-pay", invoice).run().await?;
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
    let reissue_stats = stats_for(reissues);
    let ln_sends_stats = stats_for(ln_sends);
    let ln_receives_stats = stats_for(ln_receives);
    println!(
        "================= RESULTS ==================\n\
              REISSUE: {reissue_stats}\n\
              LN SEND: {ln_sends_stats}\n\
              LN RECV: {ln_receives_stats}"
    );
    // FIXME: should be smaller
    assert!(reissue_stats.median < Duration::from_secs(4));
    assert!(ln_sends_stats.median < Duration::from_secs(6));
    assert!(ln_receives_stats.median < Duration::from_secs(6));
    let factor = 3; // FIXME: should be much smaller
    assert!(reissue_stats.p90 < reissue_stats.median * factor);
    assert!(ln_sends_stats.p90 < ln_sends_stats.median * factor);
    assert!(ln_receives_stats.p90 < ln_receives_stats.median * factor);
    let factor = 3.1f64; // FIXME: should be much smaller
    assert!(reissue_stats.max.as_secs_f64() < reissue_stats.p90.as_secs_f64() * factor);
    assert!(ln_sends_stats.max.as_secs_f64() < ln_sends_stats.p90.as_secs_f64() * factor);
    assert!(ln_receives_stats.max.as_secs_f64() < ln_receives_stats.p90.as_secs_f64() * factor);
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
        fed,
        "dev",
        "config-decrypt",
        "--in-file={data_dir}/fedimintd-0/private.encrypt",
        "--out-file={data_dir}/fedimintd-0/config-plaintext.json"
    )
    .env("FM_PASSWORD", "pass")
    .run()
    .await?;

    cmd!(
        fed,
        "dev",
        "config-encrypt",
        "--in-file={data_dir}/fedimintd-0/config-plaintext.json",
        "--out-file={data_dir}/fedimintd-0/config-2"
    )
    .env("FM_PASSWORD", "pass-foo")
    .run()
    .await?;

    cmd!(
        fed,
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

    fed.pegin_gateway(99_999, &gw_cln).await?;

    let fed_id = fed.federation_id().await;
    let invite = fed.invite_code()?;
    let invite_code = cmd!(fed, "dev", "decode-invite-code", invite.clone())
        .out_json()
        .await?;
    anyhow::ensure!(
        cmd!(
            fed,
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
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(42_000)),
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
            value_msat: 100_000,
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

    // # Client tests
    info!("Testing Client");
    // ## reissue e-cash
    info!("Testing reissuing e-cash");
    const CLIENT_START_AMOUNT: u64 = 420000;
    const CLIENT_SPEND_AMOUNT: u64 = 42;

    let initial_client_balance = fed.client_balance().await?;
    assert_eq!(initial_client_balance, 0);

    fed.pegin(CLIENT_START_AMOUNT / 1000).await?;

    // Check log contains deposit
    let operation = cmd!(fed, "list-operations")
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
    cli_tests_backup_and_restore(&fed).await?;

    // # Spend from client
    info!("Testing spending from client");
    let notes = cmd!(fed, "spend", CLIENT_SPEND_AMOUNT)
        .out_json()
        .await?
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap()
        .to_owned();

    let client_post_spend_balance = fed.client_balance().await?;
    assert_eq!(
        client_post_spend_balance,
        CLIENT_START_AMOUNT - CLIENT_SPEND_AMOUNT
    );

    // Test we can reissue our own notes
    cmd!(fed, "reissue", notes).out_json().await?;

    let client_post_spend_balance = fed.client_balance().await?;
    assert_eq!(client_post_spend_balance, CLIENT_START_AMOUNT);

    let reissue_amount: u64 = 4096;

    // Ensure that client can reissue after spending
    info!("Testing reissuing e-cash after spending");
    let _notes = cmd!(fed, "spend", CLIENT_SPEND_AMOUNT)
        .out_json()
        .await?
        .as_object()
        .unwrap()
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap();

    let reissue_notes = cmd!(fed, "spend", reissue_amount).out_json().await?["notes"]
        .as_str()
        .map(|s| s.to_owned())
        .unwrap();
    let client_reissue_amt = cmd!(fed, "reissue", reissue_notes)
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    assert_eq!(client_reissue_amt, reissue_amount);

    // Ensure that client can reissue via module commands
    info!("Testing reissuing e-cash via module commands");
    let reissue_notes = cmd!(fed, "spend", reissue_amount).out_json().await?["notes"]
        .as_str()
        .map(|s| s.to_owned())
        .unwrap();
    let client_reissue_amt = cmd!(fed, "module", "--module", "mint", "reissue", reissue_notes)
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    assert_eq!(client_reissue_amt, reissue_amount);

    // Before doing a normal payment, let's start with a HOLD invoice and only
    // finish this payment at the end
    info!("Testing fedimint-cli pays LND HOLD invoice via CLN gateway");
    let (hold_invoice_preimage, hold_invoice_hash, hold_invoice_operation_id) =
        start_hold_invoice_payment(&fed, &gw_cln, &lnd).await?;

    // OUTGOING: fedimint-cli pays LND via CLN gateway
    info!("Testing fedimint-cli pays LND via CLN gateway");
    fed.use_gateway(&gw_cln).await?;

    let initial_client_balance = fed.client_balance().await?;
    let initial_cln_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
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
    let payment_hash = add_invoice.r_hash;
    cmd!(fed, "ln-pay", invoice).run().await?;

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

    // Assert balances changed by 3000 msat (amount sent) + 0 msat (fee)
    let final_cln_outgoing_client_balance = fed.client_balance().await?;
    let final_cln_outgoing_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();

    let expected_diff = 3000;
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
        fed,
        "ln-invoice",
        "--amount=1000msat",
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
    cmd!(fed, "await-invoice", operation_id).run().await?;

    // Assert balances changed by 1000 msat
    let final_cln_incoming_client_balance = fed.client_balance().await?;
    let final_cln_incoming_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_cln_incoming_client_balance - final_cln_outgoing_client_balance == 1000,
        "Client balance changed by {} on CLN incoming payment, expected 1000",
        final_cln_incoming_client_balance - final_cln_outgoing_client_balance
    );
    anyhow::ensure!(
        final_cln_outgoing_gateway_balance - final_cln_incoming_gateway_balance == 1000,
        "CLN Gateway balance changed by {} on CLN incoming payment, expected 1000",
        final_cln_outgoing_gateway_balance - final_cln_incoming_gateway_balance
    );

    // LND gateway tests
    info!("Testing LND gateway");
    fed.use_gateway(&gw_lnd).await?;

    // OUTGOING: fedimint-cli pays CLN via LND gateaway
    info!("Testing outgoing payment from client to CLN via LND gateway");
    let initial_lnd_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    let invoice = cln
        .request(cln_rpc::model::requests::InvoiceRequest {
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(1000)),
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
    cmd!(fed, "ln-pay", invoice.clone()).run().await?;
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

    // Assert balances changed by 1000 msat (amount sent) + 0 msat (fee)
    let final_lnd_outgoing_client_balance = fed.client_balance().await?;
    let final_lnd_outgoing_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_cln_incoming_client_balance - final_lnd_outgoing_client_balance == 1000,
        "Client balance changed by {} on LND outgoing payment, expected 1000",
        final_cln_incoming_client_balance - final_lnd_outgoing_client_balance
    );
    anyhow::ensure!(
        final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance == 1000,
        "LND Gateway balance changed by {} on LND outgoing payment, expected 1000",
        final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance
    );

    // INCOMING: fedimint-cli receives from CLN via LND gateway
    info!("Testing incoming payment from CLN to client via LND gateway");
    let ln_response_val = cmd!(
        fed,
        "ln-invoice",
        "--amount=1000msat",
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
    cmd!(fed, "await-invoice", operation_id).run().await?;

    // Assert balances changed by 1000 msat
    let final_lnd_incoming_client_balance = fed.client_balance().await?;
    let final_lnd_incoming_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_lnd_incoming_client_balance - final_lnd_outgoing_client_balance == 1000,
        "Client balance changed by {} on LND incoming payment, expected 1000",
        final_lnd_incoming_client_balance - final_lnd_outgoing_client_balance
    );
    anyhow::ensure!(
        final_lnd_outgoing_gateway_balance - final_lnd_incoming_gateway_balance == 1000,
        "LND Gateway balance changed by {} on LND incoming payment, expected 1000",
        final_lnd_outgoing_gateway_balance - final_lnd_incoming_gateway_balance
    );

    info!("Will finish the payment of the LND HOLD invoice via CLN gateway");
    finish_hold_invoice_payment(
        &fed,
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
    let initial_walletng_balance = fed.client_balance().await?;

    fed.pegin(100_000).await?; // deposit in sats

    let post_deposit_walletng_balance = fed.client_balance().await?;

    assert_eq!(
        post_deposit_walletng_balance,
        initial_walletng_balance + 100_000_000 // deposit in msats
    );

    // ## Withdraw
    info!("Testing client withdraw");

    let initial_walletng_balance = fed.client_balance().await?;

    let address = bitcoind.get_new_address().await?;
    let withdraw_res = cmd!(
        fed,
        "withdraw",
        "--address",
        &address,
        "--amount",
        "5000 sat"
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
        .any(|o| o.script_pubkey == address.script_pubkey() && o.value == 5000));

    let post_withdraw_walletng_balance = fed.client_balance().await?;
    let expected_wallet_balance = initial_walletng_balance - 5_000_000 - (fees_sat * 1000);

    assert_eq!(post_withdraw_walletng_balance, expected_wallet_balance);

    Ok(())
}

async fn start_hold_invoice_payment(
    fed: &Federation,
    gw_cln: &Gatewayd,
    lnd: &Lnd,
) -> anyhow::Result<([u8; 32], cln_rpc::primitives::Sha256, String)> {
    fed.use_gateway(gw_cln).await?;
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
    let operation_id = cmd!(fed, "ln-pay", payment_request, "--finish-in-background")
        .out_json()
        .await?["operation_id"]
        .as_str()
        .context("missing operation id")?
        .to_owned();
    Ok((preimage, hash, operation_id))
}

async fn finish_hold_invoice_payment(
    fed: &Federation,
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
    let received_preimage = cmd!(fed, "await-ln-pay", hold_invoice_operation_id)
        .out_json()
        .await?["preimage"]
        .as_str()
        .context("missing preimage")?
        .to_owned();
    assert_eq!(received_preimage, hold_invoice_preimage.to_hex());
    Ok(())
}

async fn cli_load_test_tool_test(dev_fed: DevFed) -> Result<()> {
    let data_dir = env::var("FM_DATA_DIR")?;
    let load_test_temp = PathBuf::from(data_dir).join("load-test-temp");
    dev_fed.fed.pegin(10_000).await?;
    let invite_code = dev_fed.fed.invite_code()?;
    run_standard_load_test(&load_test_temp, &invite_code).await?;
    run_ln_circular_load_test(&load_test_temp, &invite_code).await?;
    Ok(())
}

async fn run_standard_load_test(load_test_temp: &Path, invite_code: &str) -> anyhow::Result<()> {
    let output = cmd!(
        "fedimint-load-test-tool",
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
        "fedimint-load-test-tool",
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

async fn run_ln_circular_load_test(load_test_temp: &Path, invite_code: &str) -> anyhow::Result<()> {
    info!("Testing ln-circular-load-test with 'two-gateways' strategy");
    let output = cmd!(
        "fedimint-load-test-tool",
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
        "fedimint-load-test-tool",
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "ln-circular-load-test",
        "--strategy",
        "partner-ping-pong",
        "--test-duration-secs",
        "2",
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
        "fedimint-load-test-tool",
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "ln-circular-load-test",
        "--strategy",
        "self-payment",
        "--test-duration-secs",
        "2",
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

async fn cli_tests_backup_and_restore(fed_cli: &Federation) -> Result<()> {
    let secret = cmd!(fed_cli, "print-secret").out_json().await?["secret"]
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap();

    let pre_notes = cmd!(fed_cli, "info").out_json().await?;

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
        let client = fed_cli.fork_client("restore-without-backup").await?;
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
        assert_eq!(pre_balance, post_balance);
    }

    // with a backup
    {
        let client = fed_cli.fork_client("restore-with-backup").await?;
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
        assert_eq!(pre_balance, post_balance);
    }

    Ok(())
}

async fn lightning_gw_reconnect_test(dev_fed: DevFed, process_mgr: &ProcessManager) -> Result<()> {
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
            match do_try_create_and_pay_invoice(&gw, &fed, &new_cln, &new_lnd).await {
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

async fn gw_reboot_test(dev_fed: DevFed, process_mgr: &ProcessManager) -> Result<()> {
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

    fed.pegin(10000).await?;

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
    let initial_client_balance = fed.client_balance().await?;
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
    cmd!(fed, "ln-pay", invoice)
        .run()
        .await
        .expect_err("Expected ln-pay to return error because the gateway is not online");
    let new_client_balance = fed.client_balance().await?;
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

async fn do_try_create_and_pay_invoice(
    gw: &Gatewayd,
    fed: &Federation,
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

    fed.use_gateway(gw).await?;
    tracing::info!("Creating invoice....");
    let ln_response_val = cmd!(
        fed,
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
    fed.terminate_server(0).await?;
    fed.generate_epochs(10).await?;

    fed.start_server(process_mgr, 0).await?;
    fed.generate_epochs(10).await?;
    fed.await_all_peers().await?;
    info!(target: LOG_DEVIMINT, "Server 0 successfully rejoined!");
    bitcoind.mine_blocks(100).await?;

    // now test what happens if consensus needs to be restarted
    fed.terminate_server(1).await?;
    bitcoind.mine_blocks(100).await?;
    fed.await_block_sync().await?;
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

    let mut fed_utxos_sats = HashSet::from([12_345_000, 23_456_000, 34_567_000]);
    for sats in &fed_utxos_sats {
        fed.pegin(*sats).await?;
    }

    // Initiate a withdrawal to verify the recoverytool recognizes change outputs
    let withdrawal_address = bitcoind.get_new_address().await?;
    let withdraw_res = cmd!(
        fed,
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
    fed.generate_epochs(2).await?;

    let now = fedimint_core::time::now();
    info!("Recovering using utxos method");
    let output = cmd!(
        "recoverytool",
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
            "recoverytool",
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
enum Cmd {
    /// Spins up bitcoind, cln, lnd, electrs, esplora, and opens a channel
    /// between the two lightning nodes
    ExternalDaemons {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
    /// Spins up bitcoind, cln w/ gateway, lnd w/ gateway, a faucet, electrs,
    /// esplora, and a federation sized from FM_FED_SIZE it opens LN channel
    /// between the two nodes. it connects the gateways to the federation.
    /// it finally switches to use the CLN gateway using the fedimint-cli
    DevFed {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
    /// Runs bitcoind, spins up FM_FED_SIZE worth of fedimints
    RunUi,
    /// `devfed` then spawns faucet for wasm tests
    WasmTestSetup {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
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
    /// Rpc commands to the long running devimint instance. Could be entry point
    /// for devimint as a cli
    #[clap(flatten)]
    Rpc(RpcCmd),
}

#[derive(Subcommand)]
enum RpcCmd {
    Wait,
    Env,
}

#[derive(Parser)]
struct CommonArgs {
    #[clap(short = 'd', long, env = "FM_TEST_DIR")]
    test_dir: Option<PathBuf>,
    #[clap(short = 'n', long, env = "FM_FED_SIZE", default_value = "4")]
    fed_size: usize,

    #[clap(long, env = "FM_LINK_TEST_DIR")]
    /// Create a link to the test dir under this path
    link_test_dir: Option<PathBuf>,
}

impl CommonArgs {
    pub fn mk_test_dir(&self) -> anyhow::Result<PathBuf> {
        let path = self.test_dir();

        std::fs::create_dir_all(&path)
            .with_context(|| format!("Creating tmp directory {}", path.display()))?;

        Ok(path)
    }

    pub fn test_dir(&self) -> PathBuf {
        self.test_dir.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("devimint-{}", std::process::id()))
        })
    }
}

#[derive(Parser)]
#[command(version)]
struct Args {
    #[clap(subcommand)]
    command: Cmd,
    #[clap(flatten)]
    common: CommonArgs,
}

async fn write_ready_file<T>(global: &vars::Global, result: Result<T>) -> Result<T> {
    let ready_file = &global.FM_READY_FILE;
    match result {
        Ok(_) => write_overwrite_async(ready_file, "READY").await?,
        Err(_) => write_overwrite_async(ready_file, "ERROR").await?,
    }
    result
}

async fn run_ui(process_mgr: &ProcessManager) -> Result<(Vec<Fedimintd>, ExternalDaemons)> {
    let externals = external_daemons(process_mgr).await?;
    let fed_size = process_mgr.globals.FM_FED_SIZE;
    let fedimintds = futures::future::try_join_all((0..fed_size).map(|peer| {
        let bitcoind = externals.bitcoind.clone();
        async move {
            let peer_port = 10000 + 8137 + peer * 2;
            let api_port = peer_port + 1;
            let metrics_port = 3510 + peer;

            let vars = vars::Fedimintd {
                FM_BIND_P2P: format!("127.0.0.1:{peer_port}"),
                FM_P2P_URL: format!("fedimint://127.0.0.1:{peer_port}"),
                FM_BIND_API: format!("127.0.0.1:{api_port}"),
                FM_API_URL: format!("ws://127.0.0.1:{api_port}"),
                FM_DATA_DIR: process_mgr
                    .globals
                    .FM_DATA_DIR
                    .join(format!("fedimintd-{peer}")),
                FM_BIND_METRICS_API: format!("127.0.0.1:{metrics_port}"),
            };
            let fm = Fedimintd::new(process_mgr, bitcoind.clone(), peer, &vars).await?;
            let server_addr = &vars.FM_BIND_API;

            poll("waiting for api startup", None, || async {
                TcpStream::connect(server_addr)
                    .await
                    .context("connect to api")
                    .map_err(ControlFlow::Continue)
            })
            .await?;

            anyhow::Ok(fm)
        }
    }))
    .await?;

    Ok((fedimintds, externals))
}

use std::fmt::Write;
use std::str::FromStr;

use fedimint_core::encoding::Decodable;

async fn setup(arg: CommonArgs) -> Result<(ProcessManager, TaskGroup)> {
    let globals = vars::Global::new(&arg.mk_test_dir()?, arg.fed_size).await?;

    let log_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(globals.FM_LOGS_DIR.join("devimint.log"))
        .await?
        .into_std()
        .await;

    fedimint_logging::TracingSetup::default()
        .with_file(Some(log_file))
        .init()?;

    if let Some(link_test_dir) = arg.link_test_dir.as_ref() {
        update_test_dir_link(link_test_dir, &arg.test_dir()).await?;
    }

    let mut env_string = String::new();
    for (var, value) in globals.vars() {
        debug!(var, value, "Env variable set");
        writeln!(env_string, r#"export {var}="{value}""#)?; // hope that value doesn't contain a "
        std::env::set_var(var, value);
    }
    write_overwrite_async(globals.FM_TEST_DIR.join("env"), env_string).await?;
    info!("Test setup in {:?}", globals.FM_DATA_DIR);
    let process_mgr = ProcessManager::new(globals);
    let task_group = TaskGroup::new();
    task_group.install_kill_handler();
    Ok((process_mgr, task_group))
}

async fn update_test_dir_link(link_test_dir: &Path, test_dir: &Path) -> Result<(), anyhow::Error> {
    if let Ok(existing) = fs::read_link(link_test_dir).await {
        if existing != test_dir {
            info!(
                old = %existing.display(),
                new = %test_dir.display(),
                link = %link_test_dir.display(),
                "Updating exinst test dir link"
            );

            fs::remove_file(link_test_dir).await?;
        }
    }
    info!(src = %test_dir.display(), dst = %link_test_dir.display(), "Linking test dir");
    fs::symlink(&test_dir, link_test_dir).await?;
    Ok(())
}

async fn cleanup_on_exit<T>(
    main_process: impl futures::Future<Output = Result<T>>,
    task_group: TaskGroup,
) -> anyhow::Result<()> {
    // This select makes it possible to exit earlier if a signal is received before
    // the main process is finished
    tokio::select! {
        _ = task_group.make_handle().make_shutdown_rx().await => {
            info!("Received shutdown signal before finishing main process, exiting early");
            Ok(())
        }
        result = main_process => {
            match result {
                Ok(v) => {
                    info!("Main process finished successfully, will wait for shutdown signal");
                    task_group.make_handle().make_shutdown_rx().await.await;
                    info!("Received shutdown signal, shutting down");
                    drop(v); // execute destructors
                    Ok(())
                },
                Err(e) => {
                    warn!("Main process failed with {e:?}, will shutdown");
                    Err(e)
                }
            }
        }
    }
}

async fn handle_command() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Cmd::ExternalDaemons { exec } => {
            let (process_mgr, task_group) = setup(args.common).await?;
            let _daemons =
                write_ready_file(&process_mgr.globals, external_daemons(&process_mgr).await)
                    .await?;
            if let Some(exec) = exec {
                exec_user_command(exec).await?;
                task_group.shutdown();
            }
            task_group.make_handle().make_shutdown_rx().await.await;
        }
        Cmd::DevFed { exec } => {
            let (process_mgr, task_group) = setup(args.common).await?;
            let main = {
                let task_group = task_group.clone();
                async move {
                    let dev_fed = dev_fed(&process_mgr).await?;
                    tokio::try_join!(
                        dev_fed.fed.pegin(10_000),
                        dev_fed.fed.pegin_gateway(20_000, &dev_fed.gw_cln),
                        dev_fed.fed.pegin_gateway(20_000, &dev_fed.gw_lnd),
                    )?;
                    let daemons = write_ready_file(&process_mgr.globals, Ok(dev_fed)).await?;

                    if let Some(exec) = exec {
                        exec_user_command(exec).await?;
                        task_group.shutdown();
                    }
                    Ok::<_, anyhow::Error>(daemons)
                }
            };
            cleanup_on_exit(main, task_group).await?;
        }
        Cmd::WasmTestSetup { exec } => {
            let (process_mgr, task_group) = setup(args.common).await?;
            let main = {
                let task_group = task_group.clone();
                async move {
                    let dev_fed = dev_fed(&process_mgr).await?;
                    let (_, _, _, faucet) = tokio::try_join!(
                        dev_fed.fed.pegin(10_000),
                        dev_fed.fed.pegin_gateway(20_000, &dev_fed.gw_cln),
                        dev_fed.fed.pegin_gateway(20_000, &dev_fed.gw_lnd),
                        async {
                            let faucet = process_mgr.spawn_daemon("faucet", cmd!("faucet")).await?;

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
        Cmd::RunUi => {
            let (process_mgr, task_group) = setup(args.common).await?;
            let main = async move {
                let result = run_ui(&process_mgr).await;
                let daemons = write_ready_file(&process_mgr.globals, result).await?;
                Ok::<_, anyhow::Error>(daemons)
            };
            cleanup_on_exit(main, task_group).await?;
        }
        Cmd::LatencyTests => {
            let (process_mgr, _) = setup(args.common).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            latency_tests(dev_fed).await?;
        }
        Cmd::ReconnectTest => {
            let (process_mgr, _) = setup(args.common).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            reconnect_test(dev_fed, &process_mgr).await?;
        }
        Cmd::CliTests => {
            let (process_mgr, _) = setup(args.common).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            cli_tests(dev_fed).await?;
        }
        Cmd::LoadTestToolTest => {
            let (process_mgr, _) = setup(args.common).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            cli_load_test_tool_test(dev_fed).await?;
        }
        Cmd::LightningReconnectTest => {
            let (process_mgr, _) = setup(args.common).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            lightning_gw_reconnect_test(dev_fed, &process_mgr).await?;
        }
        Cmd::GatewayRebootTest => {
            let (process_mgr, _) = setup(args.common).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            gw_reboot_test(dev_fed, &process_mgr).await?;
        }
        Cmd::RecoverytoolTests => {
            let (process_mgr, _) = setup(args.common).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            recoverytool_test(dev_fed).await?;
        }
        Cmd::Rpc(rpc) => rpc_command(rpc, args.common).await?,
    }
    Ok(())
}

async fn exec_user_command(exec: Vec<ffi::OsString>) -> Result<(), anyhow::Error> {
    let cmd_str = exec
        .join(ffi::OsStr::new(" "))
        .to_string_lossy()
        .to_string();
    info!(cmd = %cmd_str, "Executing user command");
    if !tokio::process::Command::new(&exec[0])
        .args(&exec[1..])
        .kill_on_drop(true)
        .status()
        .await
        .with_context(|| format!("Executing user command failed: {cmd_str}"))?
        .success()
    {
        error!(cmd = %cmd_str, "User command failed");
        return Err(anyhow!("User command failed: {cmd_str}"));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match handle_command().await {
        Ok(r) => Ok(r),
        Err(e) => {
            let ready_file = PathBuf::from(env::var("FM_TEST_DIR")?).join("ready");
            write_overwrite_async(ready_file, "ERROR").await?;
            Err(e)
        }
    }
}

async fn rpc_command(rpc: RpcCmd, common: CommonArgs) -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    match rpc {
        RpcCmd::Env => {
            let env_file = common.test_dir().join("env");
            poll("env file", None, || async {
                if fs::try_exists(&env_file)
                    .await
                    .context("env file")
                    .map_err(ControlFlow::Continue)?
                {
                    Ok(())
                } else {
                    Err(ControlFlow::Continue(anyhow!("env file not found")))
                }
            })
            .await?;
            let env = fs::read_to_string(&env_file).await?;
            print!("{env}");
            Ok(())
        }
        RpcCmd::Wait => {
            let ready_file = common.test_dir().join("ready");
            poll("ready file", 60, || async {
                if fs::try_exists(&ready_file)
                    .await
                    .context("ready file")
                    .map_err(ControlFlow::Continue)?
                {
                    Ok(())
                } else {
                    Err(ControlFlow::Continue(anyhow!("ready file not found")))
                }
            })
            .await?;
            let env = fs::read_to_string(&ready_file).await?;
            print!("{env}");

            // Append invite code to devimint env
            let test_dir = &common.test_dir();
            let env_file = test_dir.join("env");
            let invite_file = test_dir.join("cfg/invite-code");
            if fs::try_exists(&env_file).await.ok().unwrap_or(false)
                && fs::try_exists(&invite_file).await.ok().unwrap_or(false)
            {
                let invite = fs::read_to_string(&invite_file).await?;
                let mut env_string = fs::read_to_string(&env_file).await?;
                writeln!(env_string, r#"export FM_INVITE_CODE="{invite}""#)?;
                std::env::set_var("FM_INVITE_CODE", invite);
                write_overwrite_async(env_file, env_string).await?;
            }

            Ok(())
        }
    }
}
