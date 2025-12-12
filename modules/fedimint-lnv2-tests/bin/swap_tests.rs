use devimint::federation::Client;
use devimint::version_constants::VERSION_0_9_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::core::OperationId;
use fedimint_lnv2_client::FinalSendOperationState;
use lightning_invoice::Bolt11Invoice;
use tracing::info;

#[path = "common.rs"]
mod common;

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
            let (invoice, receive_op) = common::receive(&client, &gw_lnd.addr, 1_000_000).await?;
            send_lnv1(&client, &lnd_gw_id, &invoice.to_string()).await?;
            common::await_receive_claimed(&client, receive_op).await?;

            info!("Testing LNv2 client can pay LNv1 invoice...");
            let (invoice, receive_op) = receive_lnv1(&client, &lnd_gw_id, 1_000_000).await?;
            common::send(
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

async fn send_lnv1(client: &Client, gateway_id: &str, invoice: &str) -> anyhow::Result<()> {
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

async fn await_receive_lnv1(client: &Client, operation_id: OperationId) -> anyhow::Result<()> {
    let lnv1_response = cmd!(client, "await-invoice", operation_id.fmt_full())
        .out_json()
        .await?;
    assert!(lnv1_response.get("total_amount_msat").is_some());
    Ok(())
}
