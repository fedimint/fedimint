use devimint::cmd;
use devimint::federation::Client;
use fedimint_core::core::OperationId;
use fedimint_lnv2_client::{FinalReceiveOperationState, FinalSendOperationState};
use lightning_invoice::Bolt11Invoice;
use substring::Substring;

pub async fn receive(
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

pub async fn send(
    client: &Client,
    gateway: &str,
    invoice: &str,
) -> anyhow::Result<FinalSendOperationState> {
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

    await_send(client, send_op).await
}

/// Run `await-send` and parse the JSON, tolerating the pre-0.12 CLI output
/// shape so this works across the backwards-compatibility test matrix.
///
/// Pre-0.12 binaries serialize `FinalSendOperationState::Success` as the bare
/// string `"Success"` (unit variant); 0.12+ serializes it as `{"Success":
/// "<hex preimage>"}` (tuple variant carrying the preimage). Coerce the old
/// shape to a synthetic `Success(zero-preimage)` so callers can match
/// uniformly regardless of which CLI produced the output.
pub async fn await_send(
    client: &Client,
    send_op: OperationId,
) -> anyhow::Result<FinalSendOperationState> {
    let raw = cmd!(
        client,
        "module",
        "lnv2",
        "await-send",
        serde_json::to_string(&send_op)?.substring(1, 65)
    )
    .out_json()
    .await?;

    Ok(if raw.as_str() == Some("Success") {
        FinalSendOperationState::Success([0; 32])
    } else {
        serde_json::from_value(raw)?
    })
}

pub async fn await_receive_claimed(
    client: &Client,
    operation_id: OperationId,
) -> anyhow::Result<()> {
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

#[allow(dead_code)]
pub async fn receive_lnv1(
    client: &Client,
    gateway_id: &str,
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

#[allow(dead_code)]
pub async fn send_lnv1(client: &Client, gateway_id: &str, invoice: &str) -> anyhow::Result<()> {
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

#[allow(dead_code)]
pub async fn await_receive_lnv1(client: &Client, operation_id: OperationId) -> anyhow::Result<()> {
    let lnv1_response = cmd!(client, "await-invoice", operation_id.fmt_full())
        .out_json()
        .await?;
    assert!(lnv1_response.get("total_amount_msat").is_some());
    Ok(())
}
