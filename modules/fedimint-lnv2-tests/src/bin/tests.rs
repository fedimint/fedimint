use devimint::devfed::DevJitFed;
use devimint::federation::Client;
use devimint::version_constants::VERSION_0_4_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::core::OperationId;
use fedimint_core::util::SafeUrl;
use fedimint_lnv2_client::{FinalReceiveState, FinalSendState};
use lightning_invoice::Bolt11Invoice;
use substring::Substring;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = util::FedimintCli::version_or_default().await;
        let fedimintd_version = util::FedimintdCmd::version_or_default().await;
        let gatewayd_version = util::Gatewayd::version_or_default().await;

        if fedimint_cli_version < *VERSION_0_4_0_ALPHA {
            info!(%fedimint_cli_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        if fedimintd_version < *VERSION_0_4_0_ALPHA {
            info!(%fedimintd_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        if gatewayd_version < *VERSION_0_4_0_ALPHA {
            info!(%gatewayd_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        test_self_payment(&dev_fed).await?;

        test_gateway_registration(&dev_fed).await?;

        Ok(())
    })
    .await
}

async fn test_self_payment(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let federation = dev_fed.fed().await?;

    let client = federation.new_joined_client("lnv2-module-client").await?;

    federation.pegin_client(10_000, &client).await?;

    let gw_lnd = dev_fed.gw_lnd().await?;
    let gw_cln = dev_fed.gw_cln().await?;

    // TODO: test refund of payment between gateways - the refund works but it
    // causes the second payment between gateways which should be successful to
    // also be refunded but only in CI

    let inv_lnd = fetch_invoice(&client, &gw_lnd.addr).await?.0;

    // payment will be refunded due to insufficient liquidity

    test_send(&client, &gw_lnd.addr, &inv_lnd, FinalSendState::Refunded).await?;

    // only now pegin sufficient liquidity for the second payment attempts

    federation.pegin_gateway(1_000_000, gw_lnd).await?;
    federation.pegin_gateway(1_000_000, gw_cln).await?;

    let (inv_lnd, receive_op_lnd) = fetch_invoice(&client, &gw_lnd.addr).await?;
    let (inv_cln, receive_op_cln) = fetch_invoice(&client, &gw_cln.addr).await?;

    // payments will be successful since the gateways now have sufficient liquidity

    test_send(&client, &gw_lnd.addr, &inv_lnd, FinalSendState::Success).await?;
    test_send(&client, &gw_lnd.addr, &inv_cln, FinalSendState::Success).await?;

    await_receive_claimed(&client, receive_op_lnd).await?;
    await_receive_claimed(&client, receive_op_cln).await?;

    Ok(())
}

async fn fetch_invoice(
    client: &Client,
    gw_address: &String,
) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
    Ok(serde_json::from_value::<(Bolt11Invoice, OperationId)>(
        cmd!(
            client,
            "module",
            "lnv2",
            "receive",
            gw_address.clone(),
            "1000"
        )
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

async fn test_gateway_registration(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let client = dev_fed
        .fed()
        .await?
        .new_joined_client("lnv2-module-client")
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

    Ok(())
}
