use devimint::devfed::DevJitFed;
use devimint::federation::Client;
use devimint::version_constants::VERSION_0_5_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::core::OperationId;
use fedimint_core::util::SafeUrl;
use fedimint_lnv2_client::{FinalReceiveState, FinalSendState};
use lightning_invoice::Bolt11Invoice;
use substring::Substring;
use tokio::try_join;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = util::FedimintCli::version_or_default().await;
        let fedimintd_version = util::FedimintdCmd::version_or_default().await;
        let gatewayd_version = util::Gatewayd::version_or_default().await;

        if fedimint_cli_version < *VERSION_0_5_0_ALPHA {
            info!(%fedimint_cli_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        if fedimintd_version < *VERSION_0_5_0_ALPHA {
            info!(%fedimintd_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        if gatewayd_version < *VERSION_0_5_0_ALPHA {
            info!(%gatewayd_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        test_gateway_registration(&dev_fed).await?;

        let lnd = dev_fed.lnd().await?;
        let cln = dev_fed.cln().await?;

        info!("Verify HOLD invoices still work, create one now for payment later");

        let (preimage, invoice, payment_hash) = lnd.create_hold_invoice(50000).await?;

        test_payments(&dev_fed).await?;

        info!("Testing that CLN pay HOLD invoice and LND can settle HOLD invoice");

        try_join!(
            cln.pay_bolt11_invoice(invoice),
            lnd.settle_hold_invoice(preimage, payment_hash)
        )?;

        Ok(())
    })
    .await
}

async fn test_gateway_registration(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    info!("Testing gateway registration...");

    let client = dev_fed
        .fed()
        .await?
        .new_joined_client("lnv2-test-gateway-registration-client")
        .await?;

    let gw_ldk = dev_fed
        .gw_ldk_connected()
        .await?
        .as_ref()
        .expect("Gateways of version 0.5.0 or higher support LDK");

    let gateway = SafeUrl::parse(&gw_ldk.addr).expect("LDK gateway address is invalid url");

    for peer in 0..dev_fed.fed().await?.members.len() {
        assert!(add_gateway(&client, peer, &gateway.to_string()).await?);
    }

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateway", "list")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .len(),
        1
    );

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateway", "list", "--peer", "0")
            .out_json()
            .await?
            .as_array()
            .expect("JSON Value is not an array")
            .len(),
        1
    );

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateway", "select")
            .out_json()
            .await?
            .as_str()
            .expect("JSON Value is not a string"),
        gateway.to_string().as_str()
    );

    for peer in 0..dev_fed.fed().await?.members.len() {
        assert!(remove_gateway(&client, peer, &gateway).await?);
    }

    assert!(cmd!(client, "module", "lnv2", "gateway", "list")
        .out_json()
        .await?
        .as_array()
        .expect("JSON Value is not an array")
        .is_empty(),);

    assert!(
        cmd!(client, "module", "lnv2", "gateway", "list", "--peer", "0")
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

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_ldk = dev_fed
        .gw_ldk()
        .await?
        .as_ref()
        .expect("Gateways of version 0.5.0 or higher support LDK");

    let gateway_pairs = [(gw_lnd, gw_ldk), (gw_ldk, gw_lnd)];

    let gateway_matrix = [
        (gw_lnd, gw_lnd),
        (gw_lnd, gw_ldk),
        (gw_ldk, gw_lnd),
        (gw_ldk, gw_ldk),
    ];

    info!("Testing payments between gateways...");

    for (gw_send, gw_receive) in gateway_pairs {
        info!(
            "Testing payment: {} -> {}",
            gw_send.ln_type(),
            gw_receive.ln_type()
        );

        let invoice = gw_receive.create_invoice(1_000_000).await?;

        gw_send.pay_invoice(invoice).await?;
    }

    info!("Testing refund of circular payments...");

    for (gw_send, gw_receive) in gateway_matrix {
        info!(
            "Testing refund of payment: client -> {} -> {} -> client",
            gw_send.ln.as_ref().unwrap().name(),
            gw_receive.ln.as_ref().unwrap().name()
        );

        let invoice = receive(&client, &gw_receive.addr, 1_000_000).await?.0;

        test_send(&client, &gw_send.addr, &invoice, FinalSendState::Refunded).await?;
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

        test_send(&client, &gw_send.addr, &invoice, FinalSendState::Success).await?;

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

        test_send(&client, &gw_send.addr, &invoice, FinalSendState::Success).await?;
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
        "gateway",
        "add",
        gateway
    )
    .out_json()
    .await?
    .as_bool()
    .ok_or(anyhow::anyhow!("JSON Value is not a boolean"))
}

async fn remove_gateway(client: &Client, peer: usize, gateway: &SafeUrl) -> anyhow::Result<bool> {
    cmd!(
        client,
        "--our-id",
        peer.to_string(),
        "--password",
        "pass",
        "module",
        "lnv2",
        "gateway",
        "remove",
        gateway.to_string()
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
    invoice: &Bolt11Invoice,
    final_state: FinalSendState,
) -> anyhow::Result<()> {
    let send_op = serde_json::from_value::<OperationId>(
        cmd!(
            client,
            "module",
            "lnv2",
            "send",
            invoice.to_string(),
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
        serde_json::to_value(FinalReceiveState::Claimed).expect("JSON serialization failed"),
    );

    Ok(())
}
