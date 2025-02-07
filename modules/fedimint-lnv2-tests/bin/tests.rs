use anyhow::ensure;
use devimint::devfed::DevJitFed;
use devimint::federation::Client;
use devimint::version_constants::VERSION_0_7_0_ALPHA;
use devimint::{cmd, util, Gatewayd};
use fedimint_core::core::OperationId;
use fedimint_core::util::{backoff_util, retry};
use fedimint_lnv2_client::{FinalReceiveOperationState, FinalSendOperationState};
use lightning_invoice::Bolt11Invoice;
use substring::Substring;
use tokio::try_join;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        if !devimint::util::supports_lnv2() {
            info!("lnv2 is disabled, skipping");
            return Ok(());
        }

        test_gateway_registration(&dev_fed).await?;
        test_payments(&dev_fed).await?;

        Ok(())
    })
    .await
}

async fn test_gateway_registration(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let client = dev_fed
        .fed()
        .await?
        .new_joined_client("lnv2-test-gateway-registration-client")
        .await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed
        .gw_ldk_connected()
        .await?
        .as_ref()
        .expect("Gateways of version 0.5.0 or higher support LDK");

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

    assert!(gateways.contains(
        &cmd!(client, "module", "lnv2", "gateways", "select")
            .out_json()
            .await?
            .as_str()
            .expect("JSON Value is not a string")
            .to_string()
    ));

    cmd!(client, "module", "lnv2", "gateways", "map")
        .out_json()
        .await?;

    for _ in 0..10 {
        for gateway in &gateways {
            let invoice = receive(&client, gateway, 1_000_000).await?.0;

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

    assert!(cmd!(client, "module", "lnv2", "gateways", "list")
        .out_json()
        .await?
        .as_array()
        .expect("JSON Value is not an array")
        .is_empty(),);

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

    assert_eq!(client.balance().await?, 10_000 * 1000);

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed
        .gw_ldk()
        .await?
        .as_ref()
        .expect("Gateways of version 0.5.0 or higher support LDK");
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
            gw_send.ln.as_ref().unwrap().name(),
            gw_receive.ln.as_ref().unwrap().name()
        );

        let invoice = receive(&client, &gw_receive.addr, 1_000_000).await?.0;

        test_send(
            &client,
            &gw_send.addr,
            &invoice.to_string(),
            FinalSendOperationState::Refunded,
        )
        .await?;
    }

    info!("Pegging-in gateways...");

    federation
        .pegin_gateways(1_000_000, vec![gw_lnd, gw_ldk])
        .await?;

    info!("Testing circular payments...");

    for (gw_send, gw_receive) in gateway_matrix {
        info!(
            "Testing payment: client -> {} -> {} -> client",
            gw_send.ln_type(),
            gw_receive.ln_type()
        );

        let (invoice, receive_op) = receive(&client, &gw_receive.addr, 1_000_000).await?;

        test_send(
            &client,
            &gw_send.addr,
            &invoice.to_string(),
            FinalSendOperationState::Success,
        )
        .await?;

        await_receive_claimed(&client, receive_op).await?;
    }

    info!("Testing payments from client to gateways...");

    for (gw_send, gw_receive) in gateway_pairs {
        info!(
            "Testing payment: client -> {} -> {}",
            gw_send.ln_type(),
            gw_receive.ln_type()
        );

        let invoice = gw_receive.create_invoice(1_000_000).await?;

        test_send(
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
            gw_send.ln_type(),
            gw_receive.ln_type()
        );

        let (invoice, receive_op) = receive(&client, &gw_receive.addr, 1_000_000).await?;

        gw_send.pay_invoice(invoice).await?;

        await_receive_claimed(&client, receive_op).await?;
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
        test_send(
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
    // Gateway pays: 1_000 msat LNv2 federation base fee, 1_000 msat LNv2 federation
    // relative fee. Gateway receives: 1_000_000 payment.
    test_fees(fed_id, &client, gw_lnd, gw_ldk, 1_000_000 - 1_000 - 1_000).await?;

    let gatewayd_version = util::Gatewayd::version_or_default().await;
    if gatewayd_version >= *VERSION_0_7_0_ALPHA {
        info!("Testing payment summary...");
        let lnd_payment_summary = gw_lnd.payment_summary().await?;
        assert_eq!(lnd_payment_summary.outgoing.total_success, 4);
        assert_eq!(lnd_payment_summary.outgoing.total_failure, 2);
        assert_eq!(lnd_payment_summary.incoming.total_success, 3);
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
    }

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
    let (invoice, receive_op) = receive(client, &gw_ldk.addr, 1_000_000).await?;
    test_send(
        client,
        &gw_lnd.addr,
        &invoice.to_string(),
        FinalSendOperationState::Success,
    )
    .await?;
    await_receive_claimed(client, receive_op).await?;
    let gw_lnd_ecash_after = gw_lnd.ecash_balance(fed_id.clone()).await?;
    assert_eq!(gw_lnd_ecash_prev + expected_addition, gw_lnd_ecash_after);

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

async fn receive(
    client: &Client,
    gateway: &str,
    amount: u64,
) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
    Ok(serde_json::from_value::<(Bolt11Invoice, OperationId)>(
        cmd!(
            client,
            "module",
            "lnv2",
            "receive",
            amount,
            "--gateway",
            gateway
        )
        .out_json()
        .await?,
    )?)
}

async fn test_send(
    client: &Client,
    gateway: &String,
    invoice: &String,
    final_state: FinalSendOperationState,
) -> anyhow::Result<()> {
    let send_op = serde_json::from_value::<OperationId>(
        cmd!(
            client,
            "module",
            "lnv2",
            "send",
            invoice,
            "--gateway",
            gateway
        )
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
        serde_json::to_value(final_state).expect("JSON serialization failed"),
    );

    Ok(())
}

async fn await_receive_claimed(client: &Client, operation_id: OperationId) -> anyhow::Result<()> {
    assert_eq!(
        cmd!(
            client,
            "module",
            "lnv2",
            "await-receive",
            serde_json::to_string(&operation_id)?.substring(1, 65)
        )
        .out_json()
        .await?,
        serde_json::to_value(FinalReceiveOperationState::Claimed)
            .expect("JSON serialization failed"),
    );

    Ok(())
}
