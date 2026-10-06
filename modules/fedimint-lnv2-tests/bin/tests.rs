use anyhow::{bail, ensure};
use bitcoin::hashes::sha256;
use clap::{Parser, Subcommand};
use devimint::devfed::{DevFed, DevJitFed};
use devimint::federation::Client;
use devimint::util::{ProcessManager, almost_equal, poll_simple};
use devimint::version_constants::{
    VERSION_0_9_0_ALPHA, VERSION_0_10_0_ALPHA, VERSION_0_11_0_ALPHA, VERSION_0_11_4_ALPHA,
};
use devimint::{Gatewayd, cmd, util};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::Encodable;
use fedimint_core::task::{self};
use fedimint_core::util::{backoff_util, retry};
use fedimint_lnurl::{LnurlResponse, VerifyResponse, parse_lnurl};
use fedimint_lnv2_client::FinalSendOperationState;
use lightning_invoice::Bolt11Invoice;
use serde::Deserialize;
use substring::Substring;
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
    /// The gateway refuses to fund a receive while the federation cannot
    /// reach consensus
    FederationOutage,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    devimint::run_devfed_test()
        .call(|dev_fed, process_mgr| async move {
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
                Some(Commands::FederationOutage) => {
                    pegin_gateways(&dev_fed).await?;
                    let dev_fed = dev_fed.to_dev_fed(&process_mgr).await?;
                    test_federation_outage(dev_fed, &process_mgr).await?;
                }
                None => {
                    // Run all tests if no subcommand is specified
                    test_gateway_registration(&dev_fed).await?;
                    test_payments(&dev_fed).await?;
                    test_lnurl_pay(&dev_fed).await?;
                    // Last, since it takes ownership of the federation to
                    // stop and restart guardians.
                    pegin_gateways(&dev_fed).await?;
                    let dev_fed = dev_fed.to_dev_fed(&process_mgr).await?;
                    test_federation_outage(dev_fed, &process_mgr).await?;
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

        common::send(
            &client,
            &gw_send.addr,
            &invoice.to_string(),
            FinalSendOperationState::Refunded,
        )
        .await?;
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

        common::send(
            &client,
            &gw_send.addr,
            &invoice.to_string(),
            FinalSendOperationState::Success,
        )
        .await?;

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

        common::send(
            &client,
            &gw_send.addr,
            &invoice.to_string(),
            FinalSendOperationState::Success,
        )
        .await?;
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

    try_join!(
        common::send(
            &client,
            &gw_ldk.addr,
            &hold_invoice,
            FinalSendOperationState::Success
        ),
        lnd.settle_hold_invoice(hold_preimage, hold_payment_hash),
    )?;

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

    if util::FedimintdCmd::version_or_default().await >= *VERSION_0_9_0_ALPHA {
        // Gateway pays: 1_000 msat LNv2 federation base fee. Gateway receives:
        // 1_000_000 payment.
        test_fees(fed_id, &client, gw_lnd, gw_ldk, 1_000_000 - 1_000).await?;
    } else {
        // Gateway pays: 1_000 msat LNv2 federation base fee, 100 msat LNv2 federation
        // relative fee. Gateway receives: 1_000_000 payment.
        test_fees(fed_id, &client, gw_lnd, gw_ldk, 1_000_000 - 1_000 - 100).await?;
    }

    test_iroh_payment(&client, gw_lnd, gw_ldk).await?;

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

/// Stops enough guardians that no threshold of them can answer, checks that
/// a receive is refused without the gateway funding anything, then checks
/// that receives work again once the guardians are back.
async fn test_federation_outage(
    dev_fed: DevFed,
    process_mgr: &ProcessManager,
) -> anyhow::Result<()> {
    info!("Testing that the gateway refuses to fund a receive during a federation outage...");

    let DevFed {
        mut fed,
        gw_lnd,
        gw_ldk,
        ..
    } = dev_fed;

    if gw_lnd.gatewayd_version < *VERSION_0_11_4_ALPHA {
        info!(
            gatewayd_version = %gw_lnd.gatewayd_version,
            "Skipping: gateway predates the federation liveness probe"
        );
        return Ok(());
    }

    let client = fed
        .new_joined_client("lnv2-federation-outage-client")
        .await?;
    fed.await_all_peers().await?;

    let federation_id = fed.calculate_federation_id();
    let gateway = gw_lnd.client().address();

    // Register the invoice while the federation is healthy so that only the
    // funding decision is exercised below.
    let (invoice, _) = common::receive(&client, &gateway, 100_000).await?;
    let balance_before = gw_lnd.client().ecash_balance(federation_id.clone()).await?;

    // Stop the smallest number of guardians that leaves fewer than a
    // threshold of them running.
    let fed_size = process_mgr.globals.FM_FED_SIZE;
    let max_evil = (fed_size - 1) / 3;
    let stopped: Vec<usize> = (fed_size - max_evil - 1..fed_size).collect();
    for peer in &stopped {
        fed.terminate_server(*peer).await?;
    }

    info!(
        ?stopped,
        "Paying invoice while the federation cannot reach consensus"
    );
    // The payment runs concurrently: a gateway that funds anyway holds the
    // HTLC until the guardians are back, so awaiting it here would block the
    // restart below.
    let payment = fedimint_core::runtime::spawn("lnv2-outage-payment", {
        let gw_ldk = gw_ldk.client();
        async move { gw_ldk.pay_invoice(invoice).await }
    });

    // Bring the guardians back only once the gateway has acted on the HTLC:
    // a refusal fails the payment, while funding consumes ecash at submission
    // even though the transaction cannot land yet.
    poll_simple("Waiting for the gateway to act on the HTLC", || async {
        if payment.is_finished() {
            return Ok(());
        }
        let balance = gw_lnd.client().ecash_balance(federation_id.clone()).await?;
        if balance < balance_before {
            return Ok(());
        }
        bail!("gateway has not acted on the HTLC yet")
    })
    .await?;

    for peer in &stopped {
        fed.start_server(process_mgr, *peer).await?;
    }
    fed.await_all_peers().await?;

    // Funding queued during the outage would land now that the guardians are
    // back, and the payment would complete against it. The probe exists so
    // that it does not.
    let outcome = payment.await?;
    info!(?outcome, "Payment outcome once the guardians are back");
    ensure!(
        outcome.is_err(),
        "payment must fail: the gateway funded an incoming contract during the outage"
    );
    ensure!(
        gw_lnd.client().ecash_balance(federation_id.clone()).await? == balance_before,
        "gateway must not fund an incoming contract while the federation cannot reach consensus"
    );

    // The gateway's own connections to the restarted guardians come back on
    // their own schedule, and the probe refuses receives until they do, so
    // retry with a fresh invoice each time; a refused invoice is cancelled.
    info!("Paying a fresh invoice after the guardians are back");
    poll_simple("Waiting for receives to succeed again", || async {
        let (invoice, _) = common::receive(&client, &gateway, 100_000).await?;
        gw_ldk.client().pay_invoice(invoice).await
    })
    .await?;
    ensure!(
        gw_lnd.client().ecash_balance(federation_id).await? < balance_before,
        "gateway must fund the incoming contract once the federation is back"
    );

    info!("Federation outage test complete");
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

    common::send(
        client,
        &gw_lnd.addr,
        &invoice.to_string(),
        FinalSendOperationState::Success,
    )
    .await?;

    common::await_receive_claimed(client, receive_op).await?;

    let gw_lnd_ecash_after = gw_lnd.client().ecash_balance(fed_id.clone()).await?;

    almost_equal(
        gw_lnd_ecash_prev + expected_addition,
        gw_lnd_ecash_after,
        5000,
    )
    .unwrap();

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

    while client_a.balance().await? < 950 * 1000 {
        info!("Waiting for client A to receive funds via LNURL...");

        cmd!(client_a, "dev", "wait", "1").out_json().await?;
    }

    info!("Client A successfully received funds via LNURL!");

    while client_b.balance().await? < 950 * 1000 {
        info!("Waiting for client B to receive funds via LNURL...");

        cmd!(client_b, "dev", "wait", "1").out_json().await?;
    }

    info!("Client B successfully received funds via LNURL!");

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

    assert_eq!(payment_hash, *invoice.payment_hash());
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
) -> anyhow::Result<()> {
    info!("Testing iroh payment...");
    add_gateway(client, 0, &format!("iroh://{}", gw_lnd.node_id)).await?;
    add_gateway(client, 1, &format!("iroh://{}", gw_lnd.node_id)).await?;
    add_gateway(client, 2, &format!("iroh://{}", gw_lnd.node_id)).await?;
    add_gateway(client, 3, &format!("iroh://{}", gw_lnd.node_id)).await?;

    // If the client is below v0.10.0, also add the HTTP address so that the client
    // can fallback to using that, since the iroh gateway will fail.
    if util::FedimintCli::version_or_default().await < *VERSION_0_10_0_ALPHA
        || gw_lnd.gatewayd_version < *VERSION_0_10_0_ALPHA
    {
        add_gateway(client, 0, &gw_lnd.addr).await?;
        add_gateway(client, 1, &gw_lnd.addr).await?;
        add_gateway(client, 2, &gw_lnd.addr).await?;
        add_gateway(client, 3, &gw_lnd.addr).await?;
    }

    let invoice = gw_ldk.client().create_invoice(5_000_000).await?;

    let send_op = serde_json::from_value::<OperationId>(
        cmd!(client, "module", "lnv2", "send", invoice,)
            .out_json()
            .await?,
    )?;

    assert_eq!(
        cmd!(
            client,
            "module",
            "lnv2",
            "await-send",
            serde_json::to_string(&send_op)?.substring(1, 65)
        )
        .out_json()
        .await?,
        serde_json::to_value(FinalSendOperationState::Success).expect("JSON serialization failed"),
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
        remove_gateway(client, 0, &gw_lnd.addr).await?;
        remove_gateway(client, 1, &gw_lnd.addr).await?;
        remove_gateway(client, 2, &gw_lnd.addr).await?;
        remove_gateway(client, 3, &gw_lnd.addr).await?;
    }

    remove_gateway(client, 0, &format!("iroh://{}", gw_lnd.node_id)).await?;
    remove_gateway(client, 1, &format!("iroh://{}", gw_lnd.node_id)).await?;
    remove_gateway(client, 2, &format!("iroh://{}", gw_lnd.node_id)).await?;
    remove_gateway(client, 3, &format!("iroh://{}", gw_lnd.node_id)).await?;

    Ok(())
}
