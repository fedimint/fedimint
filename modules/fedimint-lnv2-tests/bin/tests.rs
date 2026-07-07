use anyhow::ensure;
use bitcoin::hashes::{Hash, sha256};
use clap::{Parser, Subcommand};
use devimint::devfed::DevJitFed;
use devimint::federation::Client;
use devimint::util::almost_equal;
use devimint::version_constants::{VERSION_0_10_0_ALPHA, VERSION_0_11_0_ALPHA};
use devimint::{Gatewayd, cmd, util};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::Encodable;
use fedimint_core::task::{self};
use fedimint_core::util::{backoff_util, retry};
use fedimint_lnurl::{LnurlResponse, VerifyResponse, parse_lnurl};
use fedimint_lnv2_client::FinalSendOperationState;
use lightning_invoice::Bolt11Invoice;
use serde::Deserialize;
use tokio::try_join;
use tracing::info;

#[path = "common.rs"]
mod common;

async fn module_is_present(client: &Client, kind: &str) -> anyhow::Result<bool> {
    let modules = cmd!(client, "module").out_json().await?;

    let modules = modules["list"].as_array().expect("module list is an array");

    Ok(modules.iter().any(|m| m["kind"].as_str() == Some(kind)))
}

async fn assert_module_sanity(client: &Client) -> anyhow::Result<()> {
    if !devimint::util::is_backwards_compatibility_test() {
        ensure!(
            !module_is_present(client, "ln").await?,
            "ln module should not be present"
        );
    }

    Ok(())
}

#[derive(Parser)]
#[command(name = "lnv2-module-tests")]
#[command(about = "LNv2 module integration tests", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run gateway registration tests
    GatewayRegistration,
    /// Run payment tests
    Payments,
    /// Run LNURL pay tests
    LnurlPay,
    /// Test LNURL receives after recovery from seed
    LnurlRecovery,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            if !devimint::util::supports_lnv2() {
                info!("lnv2 is disabled, skipping");
                return Ok(());
            }

            match &cli.command {
                Some(Commands::GatewayRegistration) => {
                    test_gateway_registration(&dev_fed).await?;
                }
                Some(Commands::Payments) => {
                    test_payments(&dev_fed).await?;
                }
                Some(Commands::LnurlPay) => {
                    pegin_gateways(&dev_fed).await?;
                    test_lnurl_pay(&dev_fed).await?;
                }
                Some(Commands::LnurlRecovery) => {
                    pegin_gateways(&dev_fed).await?;
                    test_lnurl_recovery(&dev_fed).await?;
                }
                None => {
                    // Run all tests if no subcommand is specified
                    test_gateway_registration(&dev_fed).await?;
                    test_payments(&dev_fed).await?;
                    test_lnurl_pay(&dev_fed).await?;
                    test_lnurl_recovery(&dev_fed).await?;
                }
            }

            info!("Testing LNV2 is complete!");

            Ok(())
        })
        .await
}

async fn pegin_gateways(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    info!("Pegging-in gateways...");

    let federation = dev_fed.fed().await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;

    federation
        .pegin_gateways(1_000_000, vec![gw_lnd, gw_ldk])
        .await?;

    Ok(())
}

async fn test_gateway_registration(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let client = dev_fed
        .fed()
        .await?
        .new_joined_client("lnv2-test-gateway-registration-client")
        .await?;

    assert_module_sanity(&client).await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk_connected().await?;

    let gateways = [gw_lnd.addr.clone(), gw_ldk.addr.clone()];

    info!("Testing registration of gateways...");

    for gateway in &gateways {
        for peer in 0..dev_fed.fed().await?.members.len() {
            assert!(add_gateway(&client, peer, gateway).await?);
        }
    }

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateways", "list")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .len(),
        2
    );

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateways", "list", "--peer", "0")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .len(),
        2
    );

    info!("Testing selection of gateways...");

    assert!(
        gateways.contains(
            &cmd!(client, "module", "lnv2", "gateways", "select")
                .out_json()
                .await?
                .as_str()
                .expect("JSON Value is not a string")
                .to_string()
        )
    );

    cmd!(client, "module", "lnv2", "gateways", "map")
        .out_json()
        .await?;

    for _ in 0..10 {
        for gateway in &gateways {
            let invoice = common::receive(&client, gateway, 1_000_000).await?.0;

            assert_eq!(
                cmd!(
                    client,
                    "module",
                    "lnv2",
                    "gateways",
                    "select",
                    "--invoice",
                    invoice.to_string()
                )
                .out_json()
                .await?
                .as_str()
                .expect("JSON Value is not a string"),
                gateway
            )
        }
    }

    info!("Testing deregistration of gateways...");

    for gateway in &gateways {
        for peer in 0..dev_fed.fed().await?.members.len() {
            assert!(remove_gateway(&client, peer, gateway).await?);
        }
    }

    assert!(
        cmd!(client, "module", "lnv2", "gateways", "list")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .is_empty(),
    );

    assert!(
        cmd!(client, "module", "lnv2", "gateways", "list", "--peer", "0")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .is_empty()
    );

    Ok(())
}

async fn test_payments(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let federation = dev_fed.fed().await?;

    let client = federation
        .new_joined_client("lnv2-test-payments-client")
        .await?;

    assert_module_sanity(&client).await?;

    federation.pegin_client(10_000, &client).await?;

    almost_equal(client.balance().await?, 10_000 * 1000, 500_000).unwrap();

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;
    let lnd = dev_fed.lnd().await?;

    let (hold_preimage, hold_invoice, hold_payment_hash) = lnd.create_hold_invoice(60000).await?;

    let gateway_pairs = [(gw_lnd, gw_ldk), (gw_ldk, gw_lnd)];

    let gateway_matrix = [
        (gw_lnd, gw_lnd),
        (gw_lnd, gw_ldk),
        (gw_ldk, gw_lnd),
        (gw_ldk, gw_ldk),
    ];

    info!("Testing refund of circular payments...");

    for (gw_send, gw_receive) in gateway_matrix {
        info!(
            "Testing refund of payment: client -> {} -> {} -> client",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let invoice = common::receive(&client, &gw_receive.addr, 1_000_000)
            .await?
            .0;

        let state = common::send(&client, &gw_send.addr, &invoice.to_string()).await?;
        assert!(matches!(state, FinalSendOperationState::Refunded));
    }

    pegin_gateways(dev_fed).await?;

    info!("Testing circular payments...");

    for (gw_send, gw_receive) in gateway_matrix {
        info!(
            "Testing payment: client -> {} -> {} -> client",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let (invoice, receive_op) = common::receive(&client, &gw_receive.addr, 1_000_000).await?;

        let state = common::send(&client, &gw_send.addr, &invoice.to_string()).await?;
        assert!(matches!(state, FinalSendOperationState::Success(_)));

        common::await_receive_claimed(&client, receive_op).await?;
    }

    info!("Testing payments from client to gateways...");

    for (gw_send, gw_receive) in gateway_pairs {
        info!(
            "Testing payment: client -> {} -> {}",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let invoice = gw_receive.client().create_invoice(1_000_000).await?;

        let state = common::send(&client, &gw_send.addr, &invoice.to_string()).await?;
        assert!(matches!(state, FinalSendOperationState::Success(_)));
    }

    info!("Testing payments from gateways to client...");

    for (gw_send, gw_receive) in gateway_pairs {
        info!(
            "Testing payment: {} -> {} -> client",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let (invoice, receive_op) = common::receive(&client, &gw_receive.addr, 1_000_000).await?;

        gw_send.client().pay_invoice(invoice).await?;

        common::await_receive_claimed(&client, receive_op).await?;
    }

    retry(
        "Waiting for the full balance to become available to the client".to_string(),
        backoff_util::background_backoff(),
        || async {
            ensure!(client.balance().await? >= 9000 * 1000);

            Ok(())
        },
    )
    .await?;

    info!("Testing Client can pay LND HOLD invoice via LDK Gateway...");

    let (state, _) = try_join!(
        common::send(&client, &gw_ldk.addr, &hold_invoice),
        lnd.settle_hold_invoice(hold_preimage, hold_payment_hash),
    )?;
    assert!(matches!(state, FinalSendOperationState::Success(_)));

    info!("Testing LNv2 lightning fees...");

    let fed_id = federation.calculate_federation_id();

    gw_lnd
        .client()
        .set_federation_routing_fee(fed_id.clone(), 0, 0)
        .await?;

    gw_lnd
        .client()
        .set_federation_transaction_fee(fed_id.clone(), 0, 0)
        .await?;

    // Gateway pays: 1_000 msat LNv2 federation base fee. Gateway receives:
    // 1_000_000 payment.
    test_fees(fed_id, &client, gw_lnd, gw_ldk, 1_000_000 - 1_000).await?;

    let online_peers: Vec<usize> = federation.members.keys().copied().collect();

    test_iroh_payment(&client, gw_lnd, gw_ldk, &online_peers).await?;

    info!("Testing payment summary...");

    let lnd_payment_summary = gw_lnd.client().payment_summary().await?;

    assert_eq!(lnd_payment_summary.outgoing.total_success, 5);
    assert_eq!(lnd_payment_summary.outgoing.total_failure, 2);
    assert_eq!(lnd_payment_summary.incoming.total_success, 4);
    assert_eq!(lnd_payment_summary.incoming.total_failure, 0);

    assert!(lnd_payment_summary.outgoing.median_latency.is_some());
    assert!(lnd_payment_summary.outgoing.average_latency.is_some());
    assert!(lnd_payment_summary.incoming.median_latency.is_some());
    assert!(lnd_payment_summary.incoming.average_latency.is_some());

    let ldk_payment_summary = gw_ldk.client().payment_summary().await?;

    assert_eq!(ldk_payment_summary.outgoing.total_success, 4);
    assert_eq!(ldk_payment_summary.outgoing.total_failure, 2);
    assert_eq!(ldk_payment_summary.incoming.total_success, 4);
    assert_eq!(ldk_payment_summary.incoming.total_failure, 0);

    assert!(ldk_payment_summary.outgoing.median_latency.is_some());
    assert!(ldk_payment_summary.outgoing.average_latency.is_some());
    assert!(ldk_payment_summary.incoming.median_latency.is_some());
    assert!(ldk_payment_summary.incoming.average_latency.is_some());

    Ok(())
}

async fn test_fees(
    fed_id: String,
    client: &Client,
    gw_lnd: &Gatewayd,
    gw_ldk: &Gatewayd,
    expected_addition: u64,
) -> anyhow::Result<()> {
    let gw_lnd_ecash_prev = gw_lnd.client().ecash_balance(fed_id.clone()).await?;

    let (invoice, receive_op) = common::receive(client, &gw_ldk.addr, 1_000_000).await?;

    let state = common::send(client, &gw_lnd.addr, &invoice.to_string()).await?;
    assert!(matches!(state, FinalSendOperationState::Success(_)));

    common::await_receive_claimed(client, receive_op).await?;

    // The sending gateway claims its outgoing contract in the background after
    // returning the preimage to the sender, so its ecash balance is credited
    // asynchronously. Wait for the claim to settle before asserting the fee.
    while almost_equal(
        gw_lnd_ecash_prev + expected_addition,
        gw_lnd.client().ecash_balance(fed_id.clone()).await?,
        5000,
    )
    .is_err()
    {
        info!("Waiting for the sending gateway's outgoing claim to settle...");
        cmd!(client, "dev", "wait", "1").out_json().await?;
    }

    Ok(())
}

async fn add_gateway(client: &Client, peer: usize, gateway: &String) -> anyhow::Result<bool> {
    cmd!(
        client,
        "--our-id",
        peer.to_string(),
        "--password",
        "pass",
        "module",
        "lnv2",
        "gateways",
        "add",
        gateway
    )
    .out_json()
    .await?
    .as_bool()
    .ok_or(anyhow::anyhow!("JSON Value is not a boolean"))
}

async fn remove_gateway(client: &Client, peer: usize, gateway: &String) -> anyhow::Result<bool> {
    cmd!(
        client,
        "--our-id",
        peer.to_string(),
        "--password",
        "pass",
        "module",
        "lnv2",
        "gateways",
        "remove",
        gateway
    )
    .out_json()
    .await?
    .as_bool()
    .ok_or(anyhow::anyhow!("JSON Value is not a boolean"))
}

// Keep this below the 310s `fm-run-test` timeout so LNURL flakes fail with
// useful balance diagnostics instead of a generic test timeout.
const LNURL_BALANCE_WAIT_ATTEMPTS: u64 = 120;

async fn wait_for_lnurl_balance(
    client: &Client,
    client_name: &str,
    expected_msats: u64,
) -> anyhow::Result<()> {
    let mut last_balance_msats = client.balance().await?;

    for attempt in 1..=LNURL_BALANCE_WAIT_ATTEMPTS {
        if last_balance_msats < expected_msats {
            info!(
                client_name,
                balance_msats = last_balance_msats,
                expected_msats,
                attempt,
                "Waiting for {client_name} to receive funds via LNURL"
            );
            cmd!(client, "dev", "wait", "1").out_json().await?;
            last_balance_msats = client.balance().await?;
        } else {
            info!(
                client_name,
                balance_msats = last_balance_msats,
                expected_msats,
                attempt,
                "{client_name} successfully received funds via LNURL"
            );
            return Ok(());
        }
    }

    if last_balance_msats < expected_msats {
        anyhow::bail!(
            "timed out waiting for {client_name} to receive funds via LNURL after {} attempts; last balance: {last_balance_msats} msats; expected balance: {expected_msats} msats",
            LNURL_BALANCE_WAIT_ATTEMPTS
        );
    }

    info!(
        client_name,
        balance_msats = last_balance_msats,
        expected_msats,
        attempt = LNURL_BALANCE_WAIT_ATTEMPTS,
        "{client_name} successfully received funds via LNURL"
    );

    Ok(())
}

async fn test_lnurl_pay(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    if util::FedimintCli::version_or_default().await < *VERSION_0_11_0_ALPHA {
        return Ok(());
    }

    if util::FedimintdCmd::version_or_default().await < *VERSION_0_11_0_ALPHA {
        return Ok(());
    }

    if util::Gatewayd::version_or_default().await < *VERSION_0_11_0_ALPHA {
        return Ok(());
    }

    let federation = dev_fed.fed().await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;

    let gateway_pairs = [(gw_lnd, gw_ldk), (gw_ldk, gw_lnd)];

    let recurringd = dev_fed.recurringdv2().await?.api_url().to_string();

    let client_a = federation
        .new_joined_client("lnv2-lnurl-test-client-a")
        .await?;

    assert_module_sanity(&client_a).await?;

    let client_b = federation
        .new_joined_client("lnv2-lnurl-test-client-b")
        .await?;

    assert_module_sanity(&client_b).await?;

    for (gw_send, gw_receive) in gateway_pairs {
        info!(
            "Testing lnurl payments: {} -> {} -> client",
            gw_send.ln.ln_type(),
            gw_receive.ln.ln_type()
        );

        let lnurl_a = generate_lnurl(&client_a, &recurringd, &gw_receive.addr).await?;
        let lnurl_b = generate_lnurl(&client_b, &recurringd, &gw_receive.addr).await?;

        let (invoice_a, verify_url_a) = fetch_invoice(lnurl_a.clone(), 500_000).await?;
        let (invoice_b, verify_url_b) = fetch_invoice(lnurl_b.clone(), 500_000).await?;

        let verify_task_a = task::spawn("verify_task_a", verify_payment_wait(verify_url_a.clone()));
        let verify_task_b = task::spawn("verify_task_b", verify_payment_wait(verify_url_b.clone()));

        let response_a = verify_payment(&verify_url_a).await?;
        let response_b = verify_payment(&verify_url_b).await?;

        assert!(!response_a.settled);
        assert!(!response_b.settled);

        assert!(response_a.preimage.is_none());
        assert!(response_b.preimage.is_none());

        gw_send.client().pay_invoice(invoice_a.clone()).await?;
        gw_send.client().pay_invoice(invoice_b.clone()).await?;

        let response_a = verify_payment(&verify_url_a).await?;
        let response_b = verify_payment(&verify_url_b).await?;

        assert!(response_a.settled);
        assert!(response_b.settled);

        verify_preimage(&response_a, &invoice_a);
        verify_preimage(&response_b, &invoice_b);

        assert_eq!(verify_task_a.await??, response_a);
        assert_eq!(verify_task_b.await??, response_b);
    }

    wait_for_lnurl_balance(&client_a, "client A", 950 * 1000).await?;
    wait_for_lnurl_balance(&client_b, "client B", 950 * 1000).await?;

    Ok(())
}

/// Tests LNURL receives after recovery from seed.
///
/// LNv2 uses `NoModuleBackup`, so recovery restores funds via the mint module
/// but not the operation log or LNv2 state. Verifies:
/// 1. Balance is fully recovered.
/// 2. Payments to a pre-recovery LNURL are still claimed by the restored
///    client.
async fn test_lnurl_recovery(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    // Before v0.10.0 the CLI registered LNURLs via a POST to the recurringd
    // server.  That endpoint no longer exists, so old CLIs cannot generate
    // LNURLs against the current recurringdv2.
    if util::FedimintCli::version_or_default().await < *VERSION_0_10_0_ALPHA {
        return Ok(());
    }

    let federation = dev_fed.fed().await?;
    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;
    let recurringd = dev_fed.recurringdv2().await?.api_url().to_string();

    const LNURL_AMOUNT_MSAT: u64 = 500_000;
    const LNURL_BALANCE_TOLERANCE_MSAT: u64 = 100_000;

    // ── Phase 1: Pre-recovery LNURL receives ──────────────────────────

    info!("Phase 1: Creating client and receiving via LNURL before recovery");

    let client = federation
        .new_joined_client("lnv2-lnurl-recovery-original")
        .await?;

    let lnurl = generate_lnurl(&client, &recurringd, &gw_ldk.addr).await?;

    for i in 0..3 {
        info!("Paying LNURL invoice {}/3", i + 1);
        let (invoice, _verify_url) = fetch_invoice(lnurl.clone(), LNURL_AMOUNT_MSAT).await?;
        gw_lnd.client().pay_invoice(invoice).await?;
    }

    while almost_equal(
        client.balance().await?,
        3 * LNURL_AMOUNT_MSAT,
        LNURL_BALANCE_TOLERANCE_MSAT,
    )
    .is_err()
    {
        info!("Waiting for pre-recovery LNURL payments to settle...");
        cmd!(client, "dev", "wait", "1").out_json().await?;
    }

    let pre_recovery_balance = client.balance().await?;
    info!("Pre-recovery balance: {pre_recovery_balance} msats");

    let mnemonic = cmd!(client, "print-secret").out_json().await?["secret"]
        .as_str()
        .expect("secret is a string")
        .to_owned();

    // ── Phase 2: Recovery ─────────────────────────────────────────────

    info!("Phase 2: Recovering client from seed");

    let restored = Client::create("lnv2-lnurl-recovery-restored").await?;
    cmd!(
        restored,
        "restore",
        "--invite-code",
        federation.invite_code()?,
        "--mnemonic",
        &mnemonic
    )
    .run()
    .await?;

    while restored.balance().await? < pre_recovery_balance {
        info!("Waiting for recovery to complete...");
        cmd!(restored, "dev", "wait", "1").out_json().await?;
    }

    let post_recovery_balance = restored.balance().await?;
    info!("Post-recovery balance: {post_recovery_balance} msats");

    // ── Phase 3: Post-recovery LNURL receives ─────────────────────────

    info!("Phase 3: Paying to the original LNURL; restored client must claim");

    // Reuse the Phase 1 `lnurl` on purpose: this is what a third party would
    // have saved pre-recovery, and it must still pay the restored client.
    for i in 0..2 {
        info!("Paying pre-recovery LNURL invoice {}/2", i + 1);
        let (invoice, _verify_url) = fetch_invoice(lnurl.clone(), LNURL_AMOUNT_MSAT).await?;
        gw_lnd.client().pay_invoice(invoice).await?;
    }

    while almost_equal(
        restored.balance().await?,
        post_recovery_balance + 2 * LNURL_AMOUNT_MSAT,
        LNURL_BALANCE_TOLERANCE_MSAT,
    )
    .is_err()
    {
        info!("Waiting for post-recovery LNURL payments to settle...");
        cmd!(restored, "dev", "wait", "1").out_json().await?;
    }

    let final_balance = restored.balance().await?;
    info!("Final balance: {final_balance} msats");

    let operations = cmd!(restored, "list-operations", "--limit", "100")
        .out_json()
        .await?;
    let lnv2_ops: Vec<_> = operations["operations"]
        .as_array()
        .expect("operations is an array")
        .iter()
        .filter(|op| op["operation_kind"].as_str() == Some("lnv2"))
        .collect();
    assert!(
        lnv2_ops.len() >= 2,
        "Expected at least 2 LNv2 operations after post-recovery receives, found {}",
        lnv2_ops.len()
    );

    info!(
        "LNURL recovery test passed: {} new operations, balance {final_balance} msats",
        lnv2_ops.len()
    );

    Ok(())
}

async fn generate_lnurl(
    client: &Client,
    recurringd_base_url: &str,
    gw_ldk_addr: &str,
) -> anyhow::Result<String> {
    cmd!(
        client,
        "module",
        "lnv2",
        "lnurl",
        "generate",
        recurringd_base_url,
        "--gateway",
        gw_ldk_addr,
    )
    .out_json()
    .await
    .map(|s| s.as_str().unwrap().to_owned())
}

fn verify_preimage(response: &VerifyResponse, invoice: &Bolt11Invoice) {
    let preimage = response.preimage.expect("Payment should be settled");

    let payment_hash = preimage.consensus_hash::<sha256::Hash>();

    assert_eq!(
        payment_hash,
        sha256::Hash::from_byte_array(invoice.payment_hash().0)
    );
}

async fn verify_payment(verify_url: &str) -> anyhow::Result<VerifyResponse> {
    reqwest::get(verify_url)
        .await?
        .json::<LnurlResponse<VerifyResponse>>()
        .await?
        .into_result()
        .map_err(anyhow::Error::msg)
}

async fn verify_payment_wait(verify_url: String) -> anyhow::Result<VerifyResponse> {
    reqwest::get(format!("{verify_url}?wait"))
        .await?
        .json::<LnurlResponse<VerifyResponse>>()
        .await?
        .into_result()
        .map_err(anyhow::Error::msg)
}

#[derive(Deserialize, Clone)]
struct LnUrlPayResponse {
    callback: String,
}

#[derive(Deserialize, Clone)]
struct LnUrlPayInvoiceResponse {
    pr: Bolt11Invoice,
    verify: String,
}

async fn fetch_invoice(lnurl: String, amount_msat: u64) -> anyhow::Result<(Bolt11Invoice, String)> {
    let url = parse_lnurl(&lnurl).ok_or_else(|| anyhow::anyhow!("Invalid LNURL"))?;

    let response = reqwest::get(url).await?.json::<LnUrlPayResponse>().await?;

    let callback_url = format!("{}?amount={}", response.callback, amount_msat);

    let response = reqwest::get(callback_url)
        .await?
        .json::<LnUrlPayInvoiceResponse>()
        .await?;

    ensure!(
        response.pr.amount_milli_satoshis() == Some(amount_msat),
        "Invoice amount is not set"
    );

    Ok((response.pr, response.verify))
}

async fn test_iroh_payment(
    client: &Client,
    gw_lnd: &Gatewayd,
    gw_ldk: &Gatewayd,
    online_peers: &[usize],
) -> anyhow::Result<()> {
    info!("Testing iroh payment...");
    for &peer in online_peers {
        add_gateway(client, peer, &format!("iroh://{}", gw_lnd.node_id)).await?;
    }

    // If the client is below v0.10.0, also add the HTTP address so that the client
    // can fallback to using that, since the iroh gateway will fail.
    if util::FedimintCli::version_or_default().await < *VERSION_0_10_0_ALPHA
        || gw_lnd.gatewayd_version < *VERSION_0_10_0_ALPHA
    {
        for &peer in online_peers {
            add_gateway(client, peer, &gw_lnd.addr).await?;
        }
    }

    let invoice = gw_ldk.client().create_invoice(5_000_000).await?;

    let send_op = serde_json::from_value::<OperationId>(
        cmd!(client, "module", "lnv2", "send", invoice,)
            .out_json()
            .await?,
    )?;

    let send_state = common::await_send(client, send_op).await?;
    assert!(
        matches!(send_state, FinalSendOperationState::Success(_)),
        "unexpected send state: {send_state:?}"
    );

    let (invoice, receive_op) = serde_json::from_value::<(Bolt11Invoice, OperationId)>(
        cmd!(client, "module", "lnv2", "receive", "5000000",)
            .out_json()
            .await?,
    )?;

    gw_ldk.client().pay_invoice(invoice).await?;
    common::await_receive_claimed(client, receive_op).await?;

    if util::FedimintCli::version_or_default().await < *VERSION_0_10_0_ALPHA
        || gw_lnd.gatewayd_version < *VERSION_0_10_0_ALPHA
    {
        for &peer in online_peers {
            remove_gateway(client, peer, &gw_lnd.addr).await?;
        }
    }

    for &peer in online_peers {
        remove_gateway(client, peer, &format!("iroh://{}", gw_lnd.node_id)).await?;
    }

    Ok(())
}
