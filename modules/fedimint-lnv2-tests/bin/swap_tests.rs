use devimint::federation::Client;
use devimint::version_constants::VERSION_0_9_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::core::OperationId;
use fedimint_lnv2_client::{FinalReceiveOperationState, FinalSendOperationState};
use lightning_invoice::Bolt11Invoice;
use substring::Substring;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            if !util::supports_lnv2() {
                info!("lnv2 is disabled, skipping");
                return Ok(());
            }

            let federation = dev_fed.fed().await?;

            let client = federation
                .new_joined_client("lnv1-lnv2-swap-test-client")
                .await?;

            federation.pegin_client(10_000, &client).await?;

            let gw_lnd = dev_fed.gw_lnd().await?;

            let gatewayd_version = util::Gatewayd::version_or_default().await;
            let gateway_cli_version = util::GatewayCli::version_or_default().await;

            if gatewayd_version < *VERSION_0_9_0_ALPHA || gateway_cli_version < *VERSION_0_9_0_ALPHA
            {
                info!("Gateway version too old for swap tests, skipping");
                return Ok(());
            }

            info!("Pegging-in gateway...");
            federation.pegin_gateways(1_000_000, vec![gw_lnd]).await?;

            info!("Testing LNv1 client can pay LNv2 invoice...");
            let lnd_gw_id = gw_lnd.gateway_id.clone();
            let (invoice, receive_op) = receive(&client, &gw_lnd.addr, 1_000_000).await?;
            test_send_lnv1(&client, &lnd_gw_id, &invoice.to_string()).await?;
            await_receive_claimed(&client, receive_op).await?;

            info!("Testing LNv2 client can pay LNv1 invoice...");
            let (invoice, receive_op) = receive_lnv1(&client, &lnd_gw_id, 1_000_000).await?;
            test_send(
                &client,
                &gw_lnd.addr,
                &invoice.to_string(),
                FinalSendOperationState::Success,
            )
            .await?;
            await_receive_lnv1(&client, receive_op).await?;

            info!("LNv1 <-> LNv2 swap tests complete!");

            Ok(())
        })
        .await
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

async fn receive_lnv1(
    client: &Client,
    gateway_id: &String,
    amount_msats: u64,
) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
    let invoice_response = cmd!(
        client,
        "module",
        "ln",
        "invoice",
        amount_msats,
        "--gateway-id",
        gateway_id
    )
    .out_json()
    .await?;
    let invoice = serde_json::from_value::<Bolt11Invoice>(
        invoice_response
            .get("invoice")
            .expect("Invoice should be present")
            .clone(),
    )?;
    let operation_id = serde_json::from_value::<OperationId>(
        invoice_response
            .get("operation_id")
            .expect("OperationId should be present")
            .clone(),
    )?;
    Ok((invoice, operation_id))
}

async fn test_send_lnv1(client: &Client, gateway_id: &str, invoice: &str) -> anyhow::Result<()> {
    let payment_result = cmd!(
        client,
        "module",
        "ln",
        "pay",
        invoice,
        "--gateway-id",
        gateway_id
    )
    .out_json()
    .await?;
    assert!(
        payment_result.get("Success").is_some() || payment_result.get("preimage").is_some(),
        "LNv1 payment failed: {payment_result:?}"
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

async fn await_receive_lnv1(client: &Client, operation_id: OperationId) -> anyhow::Result<()> {
    let lnv1_response = cmd!(client, "await-invoice", operation_id.fmt_full())
        .out_json()
        .await?;
    assert!(lnv1_response.get("total_amount_msat").is_some());
    Ok(())
}
