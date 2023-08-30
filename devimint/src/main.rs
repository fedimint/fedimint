use std::env;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bitcoincore_rpc::bitcoin;
use bitcoincore_rpc::bitcoin::hashes::hex::ToHex;
use bitcoincore_rpc::bitcoin::Txid;
use clap::{Parser, Subcommand};
use cln_rpc::primitives::{Amount as ClnRpcAmount, AmountOrAny};
use devimint::federation::{Federation, Fedimintd};
use devimint::util::{poll, poll_max_retries, poll_value, ProcessManager};
use devimint::{
    cmd, dev_fed, external_daemons, vars, Bitcoind, DevFed, Gatewayd, LightningNode, Lightningd,
    Lnd,
};
use fedimint_cli::LnInvoiceResponse;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::write_overwrite_async;
use fedimint_logging::LOG_DEVIMINT;
use tokio::fs;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

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
        faucet,
    } = dev_fed;

    fed.pegin(10_000_000).await?;
    let iterations = 10;
    let start_time = Instant::now();
    for _ in 0..iterations {
        let notes = cmd!(fed, "spend", "50000").out_json().await?["notes"]
            .as_str()
            .context("note must be a string")?
            .to_owned();

        cmd!(fed, "reissue", notes).run().await?;
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
        faucet,
    } = dev_fed;

    cmd!(
        fed,
        "dev",
        "config-decrypt",
        "--in-file={data_dir}/server-0/private.encrypt",
        "--out-file={data_dir}/server-0/config-plaintext.json"
    )
    .env("FM_PASSWORD", "pass")
    .run()
    .await?;

    cmd!(
        fed,
        "dev",
        "config-encrypt",
        "--in-file={data_dir}/server-0/config-plaintext.json",
        "--out-file={data_dir}/server-0/config-2"
    )
    .env("FM_PASSWORD", "pass-foo")
    .run()
    .await?;

    cmd!(
        fed,
        "dev",
        "config-decrypt",
        "--in-file={data_dir}/server-0/config-2",
        "--out-file={data_dir}/server-0/config-plaintext-2.json"
    )
    .env("FM_PASSWORD", "pass-foo")
    .run()
    .await?;

    // Test load last epoch with admin client
    info!("Testing load last epoch with admin client");
    let epoch_json = cmd!(fed, "admin", "last-epoch")
        .env("FM_PASSWORD", "pass")
        .env("FM_OUR_ID", "0")
        .out_json()
        .await?;
    let epoch_hex = epoch_json["hex_outcome"].as_str().unwrap();
    let _force_epoch = cmd!(fed, "admin", "force-epoch", epoch_hex)
        .env("FM_PASSWORD", "pass")
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
            format!(
                "--download-token={}",
                invite_code["download_token"].as_str().unwrap()
            ),
            "--id={fed_id}"
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
    info!("Testing CLN can pay LND directly");
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
    assert_eq!(operation["outcome"].as_str().unwrap(), "Claimed");

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
    let client_ng_reissue_amt = cmd!(fed, "reissue", reissue_notes)
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    assert_eq!(client_ng_reissue_amt, reissue_amount);

    // OUTGOING: fedimint-cli pays LND via CLN gateway
    info!("Testing fedimint-cli pays LND via CLN gateway");
    fed.use_gateway(&gw_cln).await?;

    let initial_client_ng_balance = fed.client_balance().await?;
    let initial_cln_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    let add_invoice = lnd
        .client_lock()
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

    // Assert balances changed by 3000 msat (amount sent) + 30 msat (fee)
    let final_cln_outgoing_client_ng_balance = fed.client_balance().await?;
    let final_cln_outgoing_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();

    let expected_diff = 3030;
    anyhow::ensure!(
        initial_client_ng_balance - final_cln_outgoing_client_ng_balance == expected_diff,
        "Client balance changed by {} on CLN outgoing payment, expected {expected_diff}",
        initial_client_ng_balance - final_cln_outgoing_client_ng_balance
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

    // Receive the ecash notes
    info!("Testing receiving e-cash notes");
    let operation_id = ln_invoice_response.operation_id;
    cmd!(fed, "wait-invoice", operation_id).run().await?;

    // Assert balances changed by 1000 msat
    let final_cln_incoming_client_ng_balance = fed.client_balance().await?;
    let final_cln_incoming_gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_cln_incoming_client_ng_balance - final_cln_outgoing_client_ng_balance == 1000,
        "Client balance changed by {} on CLN incoming payment, expected 1000",
        final_cln_incoming_client_ng_balance - final_cln_outgoing_client_ng_balance
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
        .request(cln_rpc::model::InvoiceRequest {
            amount_msat: AmountOrAny::Amount(ClnRpcAmount::from_msat(1000)),
            description: "lnd-gw-to-cln".to_string(),
            label: "test-client".to_string(),
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

    // Assert balances changed by 1000 msat (amount sent) + 10 msat (fee)
    let final_lnd_outgoing_client_ng_balance = fed.client_balance().await?;
    let final_lnd_outgoing_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_cln_incoming_client_ng_balance - final_lnd_outgoing_client_ng_balance == 1010,
        "Client balance changed by {} on LND outgoing payment, expected 1010",
        final_cln_incoming_client_ng_balance - final_lnd_outgoing_client_ng_balance
    );
    anyhow::ensure!(
        final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance == 1010,
        "LND Gateway balance changed by {} on LND outgoing payment, expected 1010",
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

    // Receive the ecash notes
    info!("Testing receiving ecash notes");
    let operation_id = ln_invoice_response.operation_id;
    cmd!(fed, "wait-invoice", operation_id).run().await?;

    // Assert balances changed by 1000 msat
    let final_lnd_incoming_client_ng_balance = fed.client_balance().await?;
    let final_lnd_incoming_gateway_balance = cmd!(gw_lnd, "balance", "--federation-id={fed_id}")
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    anyhow::ensure!(
        final_lnd_incoming_client_ng_balance - final_lnd_outgoing_client_ng_balance == 1000,
        "Client balance changed by {} on LND incoming payment, expected 1000",
        final_lnd_incoming_client_ng_balance - final_lnd_outgoing_client_ng_balance
    );
    anyhow::ensure!(
        final_lnd_outgoing_gateway_balance - final_lnd_incoming_gateway_balance == 1000,
        "LND Gateway balance changed by {} on LND incoming payment, expected 1000",
        final_lnd_outgoing_gateway_balance - final_lnd_incoming_gateway_balance
    );

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

    let tx_hex = poll_value("Waiting for transaction in mempool", || async {
        // TODO: distinguish errors from not found
        Ok(bitcoind.get_raw_transaction(&txid).await.ok())
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

async fn cli_load_test_tool_test(dev_fed: DevFed) -> Result<()> {
    let data_dir = env::var("FM_DATA_DIR")?;
    let load_test_temp = PathBuf::from(data_dir).join("load-test-temp");
    dev_fed.fed.pegin(10_000).await?;
    let invite_code = dev_fed.fed.invite_code()?;
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
        invite_code.clone()
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

async fn cli_tests_backup_and_restore(fed_cli: &Federation) -> Result<()> {
    let secret = cmd!(fed_cli, "print-secret").out_json().await?["secret"]
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap();

    let pre_notes = cmd!(fed_cli, "info").out_json().await?;

    let pre_balance = pre_notes["total_msat"].as_u64().unwrap();

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
            cmd!(client, "info").out_json().await?["total_msat"]
                .as_u64()
                .unwrap()
        );
        let _ = cmd!(client, "restore", &secret,).out_json().await?;

        let post_notes = cmd!(client, "info").out_json().await?;
        let post_balance = post_notes["total_msat"].as_u64().unwrap();

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
            cmd!(client, "info").out_json().await?["total_msat"]
                .as_u64()
                .unwrap()
        );
        let _ = cmd!(client, "restore", &secret,).out_json().await?;

        let post_notes = cmd!(client, "info").out_json().await?;
        let post_balance = post_notes["total_msat"].as_u64().unwrap();

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
        faucet,
    } = dev_fed;

    fed.pegin_gateway(99_999, &gw_cln).await?;
    fed.pegin_gateway(99_999, &gw_lnd).await?;

    // Drop other references to CLN and LND so that the test can kill them
    drop(cln);
    drop(lnd);

    let mut gateways = vec![gw_cln, gw_lnd];

    tracing::info!("Stopping the lightning nodes...");
    for gw in &mut gateways {
        // Verify that the gateway can query the lightning node for the pubkey and alias
        let mut info_cmd = cmd!(gw, "info");
        assert!(info_cmd.run().await.is_ok());

        // Verify that after stopping the lightning node, info no longer returns since
        // the lightning node is unreachable.
        gw.stop_lightning_node().await?;
        let info_fut = info_cmd.run();

        // CLN will timeout when trying to retrieve the info, LND will return an
        // explicit error
        let expected_timeout_or_failure = tokio::time::timeout(Duration::from_secs(3), info_fut)
            .await
            .map_err(Into::into)
            .and_then(|result| result);
        assert!(expected_timeout_or_failure.is_err());
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

    info!(LOG_DEVIMINT, "lightning_reconnect_test: success");
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
    poll("Waiting for info to succeed after restart", || async {
        let mut info_cmd = cmd!(gw, "info");
        Ok(info_cmd
            .run()
            .await
            .map_err(|e| warn!("Info command not ready yet, retrying: {e}"))
            .is_ok())
    })
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
                .client_lock()
                .await?
                .send_payment_sync(tonic_lnd::lnrpc::SendRequest {
                    payment_request: invoice.clone(),
                    ..Default::default()
                })
                .await?
                .into_inner();

            let payment_status = new_lnd
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
        Some(LightningNode::Lnd(_lnd)) => {
            // Pay the invoice using CLN
            let invoice_status = new_cln
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
        faucet,
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
    info!(LOG_DEVIMINT, "Server 0 successfully rejoined!");
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

    poll_max_retries("federation back online", 15, || async {
        fed.await_all_peers().await?;
        Ok(true)
    })
    .await?;

    info!(LOG_DEVIMINT, "fm success: reconnect-test");
    Ok(())
}

#[derive(Subcommand)]
enum Cmd {
    ExternalDaemons,
    DevFed,
    RunUi,
    LatencyTests,
    ReconnectTest,
    CliTests,
    LoadTestToolTest,
    LightningReconnectTest,
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
    test_dir: PathBuf,
    #[clap(short = 'n', long, env = "FM_FED_SIZE")]
    fed_size: usize,
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

async fn run_ui(process_mgr: &ProcessManager) -> Result<Vec<Fedimintd>> {
    let bitcoind = Bitcoind::new(process_mgr).await?;
    let fed_size = process_mgr.globals.FM_FED_SIZE;
    let fedimintds = futures::future::try_join_all((0..fed_size).map(|peer| {
        let bitcoind = bitcoind.clone();
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
                    .join(format!("server-{peer}")),
                FM_BIND_METRICS_API: format!("127.0.0.1:{metrics_port}"),
            };
            let fm = Fedimintd::new(process_mgr, bitcoind.clone(), peer, &vars).await?;
            let server_addr = &vars.FM_BIND_API;

            poll("waiting for ui/api startup", || async {
                Ok(TcpStream::connect(server_addr).await.is_ok())
            })
            .await?;

            anyhow::Ok(fm)
        }
    }))
    .await?;

    Ok(fedimintds)
}

use std::fmt::Write;
use std::str::FromStr;

use fedimint_core::encoding::Decodable;

async fn setup(arg: CommonArgs) -> Result<(ProcessManager, TaskGroup)> {
    let globals = vars::Global::new(&arg.test_dir, arg.fed_size).await?;
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

    let mut env_string = String::new();
    for (var, value) in globals.vars() {
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
        Cmd::ExternalDaemons => {
            let (process_mgr, task_group) = setup(args.common).await?;
            let _daemons =
                write_ready_file(&process_mgr.globals, external_daemons(&process_mgr).await)
                    .await?;
            task_group.make_handle().make_shutdown_rx().await.await;
        }
        Cmd::DevFed => {
            let (process_mgr, task_group) = setup(args.common).await?;
            let main = async move {
                let dev_fed = dev_fed(&process_mgr).await?;
                dev_fed.fed.pegin(10_000).await?;
                dev_fed.fed.pegin_gateway(20_000, &dev_fed.gw_cln).await?;
                dev_fed.fed.pegin_gateway(20_000, &dev_fed.gw_lnd).await?;
                let daemons = write_ready_file(&process_mgr.globals, Ok(dev_fed)).await?;
                Ok::<_, anyhow::Error>(daemons)
            };
            cleanup_on_exit(main, task_group).await?;
        }
        Cmd::RunUi => {
            let (process_mgr, task_group) = setup(args.common).await?;
            let main = async move {
                let fedimintds = run_ui(&process_mgr).await?;
                let daemons = write_ready_file(&process_mgr.globals, Ok(fedimintds)).await?;
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
        Cmd::Rpc(rpc) => rpc_command(rpc, args.common).await?,
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let ready_file = PathBuf::from(env::var("FM_TEST_DIR")?).join("ready");
    match handle_command().await {
        Ok(r) => Ok(r),
        Err(e) => {
            write_overwrite_async(ready_file, "ERROR").await?;
            Err(e)
        }
    }
}

async fn rpc_command(rpc: RpcCmd, common: CommonArgs) -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    match rpc {
        RpcCmd::Env => {
            let env_file = common.test_dir.join("env");
            poll("env file", || async {
                Ok(fs::try_exists(&env_file).await?)
            })
            .await?;
            let env = fs::read_to_string(&env_file).await?;
            print!("{env}");
            Ok(())
        }
        RpcCmd::Wait => {
            let ready_file = common.test_dir.join("ready");
            poll("ready file", || async {
                Ok(fs::try_exists(&ready_file).await?)
            })
            .await?;
            let env = fs::read_to_string(&ready_file).await?;
            print!("{env}");
            Ok(())
        }
    }
}
