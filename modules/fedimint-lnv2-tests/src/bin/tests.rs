use clap::Parser;
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

#[derive(Parser)]
enum TestOpts {
    All,
    GatewayRegistration,
    SelfPaymentsRefund,
    SelfPaymentsSuccess,
    LightningPayment,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = TestOpts::parse();

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

        match opts {
            TestOpts::All => {
                test_gateway_registration(&dev_fed).await?;
                test_self_payments_refund(&dev_fed).await?;

                pegin_gateways(&dev_fed).await?;

                test_self_payments_success(&dev_fed).await?;
                test_lightning_payments(&dev_fed).await?;
            }
            TestOpts::GatewayRegistration => {
                test_gateway_registration(&dev_fed).await?;
            }
            TestOpts::SelfPaymentsRefund => {
                test_self_payments_refund(&dev_fed).await?;
            }
            TestOpts::SelfPaymentsSuccess => {
                pegin_gateways(&dev_fed).await?;
                test_self_payments_success(&dev_fed).await?;
            }
            TestOpts::LightningPayment => {
                pegin_gateways(&dev_fed).await?;
                test_lightning_payments(&dev_fed).await?;
            }
        }

        Ok(())
    })
    .await
}

async fn pegin_gateways(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    info!("Pegging-in gateways...");

    let federation = dev_fed.fed().await?;

    let gw_lnd = dev_fed.gw_lnd_registered().await?;
    let gw_cln = dev_fed.gw_cln_registered().await?;

    federation.pegin_gateway(1_000_000, gw_lnd).await?;
    federation.pegin_gateway(1_000_000, gw_cln).await?;

    info!("Pegging-in gateways successful");

    Ok(())
}

async fn test_gateway_registration(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    info!("Testing gateway registration...");

    let client = dev_fed
        .fed()
        .await?
        .new_joined_client("lnv2-gateway-registration-client")
        .await?;

    let gateway = SafeUrl::parse("https://gateway.xyz").expect("Valid Url");

    assert_eq!(
        cmd!(
            client,
            "--our-id",
            "0",
            "--password",
            "pass",
            "module",
            "lnv2",
            "add-gateway",
            gateway.clone().to_string(),
        )
        .out_json()
        .await?,
        serde_json::to_value(true).expect("JSON serialization failed")
    );

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateways", "0")
            .out_json()
            .await?,
        serde_json::to_value(vec![gateway.clone()]).expect("JSON serialization failed")
    );

    assert_eq!(
        cmd!(
            client,
            "--our-id",
            "0",
            "--password",
            "pass",
            "module",
            "lnv2",
            "remove-gateway",
            gateway.to_string(),
        )
        .out_json()
        .await?,
        serde_json::to_value(true).expect("JSON serialization failed")
    );

    assert_eq!(
        cmd!(client, "module", "lnv2", "gateways", "0",)
            .out_json()
            .await?,
        serde_json::to_value(Vec::<SafeUrl>::new()).expect("JSON serialization failed")
    );

    info!("Testing gateway registration successful");

    Ok(())
}

async fn test_self_payments_refund(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    info!("Testing self payments refund...");

    let federation = dev_fed.fed().await?;

    let client = federation
        .new_joined_client("lnv2-self-payments-refund-client")
        .await?;

    federation.pegin_client(10_000, &client).await?;

    let gw_lnd = dev_fed.gw_lnd_registered().await?;
    let gw_cln = dev_fed.gw_cln_registered().await?;

    for (gw_receive, gw_send) in [
        (gw_lnd.addr.clone(), gw_lnd.addr.clone()),
        (gw_lnd.addr.clone(), gw_cln.addr.clone()),
        (gw_cln.addr.clone(), gw_lnd.addr.clone()),
        (gw_cln.addr.clone(), gw_cln.addr.clone()),
    ] {
        info!("Testing self payment refund: {gw_send} -> {gw_receive}");

        let invoice = receive(&client, &gw_receive, 1_000_000).await?.0;

        test_send(&client, &gw_send, &invoice, FinalSendState::Refunded).await?;
    }

    info!("Testing self payments refund successful");

    Ok(())
}

async fn test_self_payments_success(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    info!("Testing self payments success...");

    let federation = dev_fed.fed().await?;

    let client = federation
        .new_joined_client("lnv2-self-payments-success-client")
        .await?;

    federation.pegin_client(10_000, &client).await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_cln = dev_fed.gw_cln().await?;

    for (gw_receive, gw_send) in [
        (gw_lnd.addr.clone(), gw_lnd.addr.clone()),
        (gw_lnd.addr.clone(), gw_cln.addr.clone()),
        (gw_cln.addr.clone(), gw_lnd.addr.clone()),
        (gw_cln.addr.clone(), gw_cln.addr.clone()),
    ] {
        info!("Testing self payment success: {gw_send} -> {gw_receive}");

        let (invoice, receive_op) = receive(&client, &gw_receive, 1_000_000).await?;

        test_send(&client, &gw_send, &invoice, FinalSendState::Success).await?;

        await_receive_claimed(&client, receive_op).await?;
    }

    info!("Testing self payments success successful");

    Ok(())
}

async fn test_lightning_payments(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    info!("Testing lightning payments...");

    let federation = dev_fed.fed().await?;

    let client = federation
        .new_joined_client("lnv2-lightning-payments-client")
        .await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_cln = dev_fed.gw_cln().await?;

    let lnd = dev_fed.lnd().await?;
    let cln = dev_fed.cln().await?;

    info!("Verify HOLD invoices still work, create one now for payment later");

    let (hold_preimage, hold_invoice, hold_payment_hash) = lnd.create_hold_invoice(50000).await?;

    info!("Testing that CLN can pay LND directly");

    let (invoice, payment_hash) = lnd.invoice(5000).await?;

    cln.pay_bolt11_invoice(invoice).await?;
    lnd.wait_bolt11_invoice(payment_hash).await?;

    info!("Testing that CLN can pay client via LND Gateway");

    let (inv_lnd, receive_op_lnd) = receive(&client, &gw_lnd.addr, 500_000).await?;

    cln.pay_bolt11_invoice(inv_lnd.to_string()).await?;

    await_receive_claimed(&client, receive_op_lnd).await?;

    info!("Testing that LND can pay CLN directly");

    let invoice = cln
        .invoice(
            5000,
            "lnd-pay-cln-directly".to_string(),
            "lnd-pay-cln-directly".to_string(),
        )
        .await?;

    lnd.pay_bolt11_invoice(invoice).await?;
    cln.wait_any_bolt11_invoice().await?;

    info!("Testing that LND can pay client via CLN gateway");

    let (inv_cln, receive_op_cln) = receive(&client, &gw_cln.addr, 750_000).await?;

    lnd.pay_bolt11_invoice(inv_cln.to_string()).await?;

    await_receive_claimed(&client, receive_op_cln).await?;

    info!("Testing that CLN pay HOLD invoice and LND can settle HOLD invoice");

    try_join!(
        cln.pay_bolt11_invoice(hold_invoice),
        lnd.settle_hold_invoice(hold_preimage, hold_payment_hash)
    )?;

    info!("Testing lightning payments successful");

    Ok(())
}

async fn receive(
    client: &Client,
    gw_address: &str,
    amount: u64,
) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
    Ok(serde_json::from_value::<(Bolt11Invoice, OperationId)>(
        cmd!(client, "module", "lnv2", "receive", gw_address, amount,)
            .out_json()
            .await?,
    )?)
}

async fn test_send(
    client: &Client,
    gw_address: &String,
    invoice: &Bolt11Invoice,
    final_state: FinalSendState,
) -> anyhow::Result<()> {
    let send_op = serde_json::from_value::<OperationId>(
        cmd!(
            client,
            "module",
            "lnv2",
            "send",
            gw_address,
            invoice.to_string()
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
