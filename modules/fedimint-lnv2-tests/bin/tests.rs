use std::str::FromStr;

use anyhow::ensure;
use bitcoin::hashes::sha256;
use clap::{Parser, Subcommand};
use devimint::devfed::DevJitFed;
use devimint::federation::Client;
use devimint::util::almost_equal;
use devimint::version_constants::{VERSION_0_9_0_ALPHA, VERSION_0_10_0_ALPHA};
use devimint::{Gatewayd, cmd, util};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::Encodable;
use fedimint_core::task::{self};
use fedimint_core::util::{backoff_util, retry};
use fedimint_lnv2_client::FinalSendOperationState;
use fedimint_lnv2_common::lnurl::VerifyResponse;
use lightning_invoice::Bolt11Invoice;
use lnurl::lnurl::LnUrl;
use serde::Deserialize;
use substring::Substring;
use tokio::try_join;
use tracing::info;

#[path = "common.rs"]
mod common;

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

            if !devimint::util::is_backwards_compatibility_test() {
                info!("Verifying that LNv1 module is disabled...");

                ensure!(
                    !devimint::util::supports_lnv1(),
                    "LNv1 module should be disabled when not in backwards compatibility test"
                );
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
                    test_lnurl_pay(&dev_fed, false).await?;
                    test_lnurl_pay(&dev_fed, true).await?;
                }
                None => {
                    // Run all tests if no subcommand is specified
                    test_gateway_registration(&dev_fed).await?;
                    test_payments(&dev_fed).await?;
                    test_lnurl_pay(&dev_fed, false).await?;
                    test_lnurl_pay(&dev_fed, true).await?;
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

        let invoice = gw_receive.create_invoice(1_000_000).await?;

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

        gw_send.pay_invoice(invoice).await?;

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
        .set_federation_routing_fee(fed_id.clone(), 0, 0)
        .await?;

    gw_lnd
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

    let lnd_payment_summary = gw_lnd.payment_summary().await?;

    assert_eq!(lnd_payment_summary.outgoing.total_success, 5);
    assert_eq!(lnd_payment_summary.outgoing.total_failure, 2);
    assert_eq!(lnd_payment_summary.incoming.total_success, 4);
    assert_eq!(lnd_payment_summary.incoming.total_failure, 0);

    assert!(lnd_payment_summary.outgoing.median_latency.is_some());
    assert!(lnd_payment_summary.outgoing.average_latency.is_some());
    assert!(lnd_payment_summary.incoming.median_latency.is_some());
    assert!(lnd_payment_summary.incoming.average_latency.is_some());

    let ldk_payment_summary = gw_ldk.payment_summary().await?;

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
    let gw_lnd_ecash_prev = gw_lnd.ecash_balance(fed_id.clone()).await?;

    let (invoice, receive_op) = common::receive(client, &gw_ldk.addr, 1_000_000).await?;

    common::send(
        client,
        &gw_lnd.addr,
        &invoice.to_string(),
        FinalSendOperationState::Success,
    )
    .await?;

    common::await_receive_claimed(client, receive_op).await?;

    let gw_lnd_ecash_after = gw_lnd.ecash_balance(fed_id.clone()).await?;

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

async fn test_lnurl_pay(dev_fed: &DevJitFed, use_v2: bool) -> anyhow::Result<()> {
    let min_version = if use_v2 {
        &*VERSION_0_10_0_ALPHA
    } else {
        &*VERSION_0_9_0_ALPHA
    };

    if util::FedimintCli::version_or_default().await < *min_version {
        return Ok(());
    }

    if util::FedimintdCmd::version_or_default().await < *min_version {
        return Ok(());
    }

    if util::Gatewayd::version_or_default().await < *min_version {
        return Ok(());
    }

    let federation = dev_fed.fed().await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed.gw_ldk().await?;

    let gateway_pairs = [(gw_lnd, gw_ldk), (gw_ldk, gw_lnd)];

    let recurringd = if use_v2 {
        dev_fed.recurringdv2().await?.api_url().to_string()
    } else {
        dev_fed.recurringd().await?.api_url().to_string()
    };

    let client_a = federation
        .new_joined_client("lnv2-lnurl-test-client-a")
        .await?;

    let client_b = federation
        .new_joined_client("lnv2-lnurl-test-client-b")
        .await?;

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

        gw_send.pay_invoice(invoice_a.clone()).await?;
        gw_send.pay_invoice(invoice_b.clone()).await?;

        let response_a = verify_payment(&verify_url_a).await?;
        let response_b = verify_payment(&verify_url_b).await?;

        assert!(response_a.settled);
        assert!(response_b.settled);

        let payment_hash = response_a
            .preimage
            .expect("Payment A should be settled")
            .consensus_hash::<sha256::Hash>();

        assert_eq!(payment_hash, *invoice_a.payment_hash());

        let payment_hash = response_b
            .preimage
            .expect("Payment B should be settled")
            .consensus_hash::<sha256::Hash>();

        assert_eq!(payment_hash, *invoice_b.payment_hash());

        assert_eq!(verify_task_a.await??.preimage, response_a.preimage);
        assert_eq!(verify_task_b.await??.preimage, response_b.preimage);
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

async fn verify_payment(verify_url: &str) -> anyhow::Result<VerifyResponse> {
    let response = reqwest::get(verify_url)
        .await?
        .json::<VerifyResponse>()
        .await?;

    Ok(response)
}

async fn verify_payment_wait(verify_url: String) -> anyhow::Result<VerifyResponse> {
    let response = reqwest::get(format!("{verify_url}?wait"))
        .await?
        .json::<VerifyResponse>()
        .await?;

    Ok(response)
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
    let endpoint = LnUrl::from_str(&lnurl)?;

    let response = reqwest::get(endpoint.url)
        .await?
        .json::<LnUrlPayResponse>()
        .await?;

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

    let invoice = gw_ldk.create_invoice(5_000_000).await?;

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

    gw_ldk.pay_invoice(invoice).await?;
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
