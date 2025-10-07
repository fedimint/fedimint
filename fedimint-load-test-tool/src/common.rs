use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use devimint::cmd;
use devimint::util::{FedimintCli, GatewayLdkCli, LnCli};
use devimint::version_constants::VERSION_0_7_0_ALPHA;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::transaction::TransactionBuilder;
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_core::core::{IntoDynInstance, OperationId};
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::util::backoff_util::aggressive_backoff;
use fedimint_core::util::retry;
use fedimint_core::{Amount, OutPoint, PeerId, TieredCounts, secp256k1};
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, LnPayState, OutgoingLightningPayment,
};
use fedimint_ln_common::LightningGateway;
use fedimint_mint_client::{
    MintClientInit, MintClientModule, MintCommonInit, OOBNotes, SelectNotesWithAtleastAmount,
};
use fedimint_wallet_client::WalletClientInit;
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::MetricEvent;

pub async fn get_invite_code_cli(peer: PeerId) -> anyhow::Result<InviteCode> {
    cmd!(FedimintCli, "invite-code", peer).out_json().await?["invite_code"]
        .as_str()
        .map(InviteCode::from_str)
        .transpose()?
        .context("missing invite code")
}

pub async fn get_notes_cli(amount: &Amount) -> anyhow::Result<OOBNotes> {
    cmd!(FedimintCli, "spend", amount.msats.to_string())
        .out_json()
        .await?["notes"]
        .as_str()
        .map(OOBNotes::from_str)
        .transpose()?
        .context("missing notes output")
}

pub async fn try_get_notes_cli(amount: &Amount, tries: usize) -> anyhow::Result<OOBNotes> {
    for _ in 0..tries {
        match get_notes_cli(amount).await {
            Ok(oob_notes) => return Ok(oob_notes),
            Err(e) => {
                info!("Failed to get notes from cli: {e}, trying again after a second...");
                fedimint_core::task::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    get_notes_cli(amount).await
}

pub async fn reissue_notes(
    client: &ClientHandleArc,
    oob_notes: OOBNotes,
    event_sender: &mpsc::UnboundedSender<MetricEvent>,
) -> anyhow::Result<()> {
    let m = fedimint_core::time::now();
    let mint = &client.get_first_module::<MintClientModule>()?;
    let operation_id = mint.reissue_external_notes(oob_notes, ()).await?;
    let mut updates = mint
        .subscribe_reissue_external_notes(operation_id)
        .await?
        .into_stream();
    while let Some(update) = updates.next().await {
        if let fedimint_mint_client::ReissueExternalNotesState::Failed(e) = update {
            bail!("Reissue failed: {e}")
        }
    }
    event_sender.send(MetricEvent {
        name: "reissue_notes".into(),
        duration: m.elapsed()?,
    })?;
    Ok(())
}

pub async fn do_spend_notes(
    mint: &ClientHandleArc,
    amount: Amount,
) -> anyhow::Result<(OperationId, OOBNotes)> {
    let mint = &mint.get_first_module::<MintClientModule>()?;
    let (operation_id, oob_notes) = mint
        .spend_notes_with_selector(
            &SelectNotesWithAtleastAmount,
            amount,
            Duration::from_secs(600),
            false,
            (),
        )
        .await?;
    let mut updates = mint
        .subscribe_spend_notes(operation_id)
        .await?
        .into_stream();
    if let Some(update) = updates.next().await {
        match update {
            fedimint_mint_client::SpendOOBState::Created
            | fedimint_mint_client::SpendOOBState::Success => {}
            other => {
                bail!("Spend failed: {other:?}");
            }
        }
    }
    Ok((operation_id, oob_notes))
}

pub async fn await_spend_notes_finish(
    client: &ClientHandleArc,
    operation_id: OperationId,
) -> anyhow::Result<()> {
    let mut updates = client
        .get_first_module::<MintClientModule>()?
        .subscribe_spend_notes(operation_id)
        .await?
        .into_stream();
    while let Some(update) = updates.next().await {
        info!("SpendOOBState update: {:?}", update);
        match update {
            fedimint_mint_client::SpendOOBState::Created
            | fedimint_mint_client::SpendOOBState::Success => {}
            other => {
                bail!("Spend failed: {other:?}");
            }
        }
    }
    Ok(())
}

pub async fn build_client(
    invite_code: Option<InviteCode>,
    rocksdb: Option<&PathBuf>,
) -> anyhow::Result<(ClientHandleArc, Option<InviteCode>)> {
    let db = if let Some(rocksdb) = rocksdb {
        Database::new(
            fedimint_rocksdb::RocksDb::open(rocksdb).await?,
            ModuleRegistry::default(),
        )
    } else {
        fedimint_core::db::mem_impl::MemDatabase::new().into()
    };
    let mut client_builder = Client::builder(db)
        .await?
        .with_iroh_enable_dht(false)
        .with_iroh_enable_dht(false);
    client_builder.with_module(MintClientInit);
    client_builder.with_module(LightningClientInit::default());
    client_builder.with_module(WalletClientInit::default());
    client_builder.with_primary_module_kind(fedimint_mint_client::KIND);
    let client_secret =
        Client::load_or_generate_client_secret(client_builder.db_no_decoders()).await?;
    let root_secret =
        RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(&client_secret));

    let client = if Client::is_initialized(client_builder.db_no_decoders()).await {
        client_builder.open(root_secret).await
    } else if let Some(invite_code) = &invite_code {
        client_builder
            .preview(invite_code)
            .await?
            .join(root_secret)
            .await
    } else {
        bail!("Database not initialize and invite code not provided");
    }?;
    Ok((Arc::new(client), invite_code))
}

pub async fn lnd_create_invoice(amount: Amount) -> anyhow::Result<(Bolt11Invoice, String)> {
    let result = cmd!(LnCli, "addinvoice", "--amt_msat", amount.msats)
        .out_json()
        .await?;
    let invoice = result["payment_request"]
        .as_str()
        .map(Bolt11Invoice::from_str)
        .transpose()?
        .context("Missing payment_request field")?;
    let r_hash = result["r_hash"]
        .as_str()
        .context("Missing r_hash field")?
        .to_owned();
    Ok((invoice, r_hash))
}

pub async fn lnd_pay_invoice(invoice: Bolt11Invoice) -> anyhow::Result<()> {
    let status = cmd!(
        LnCli,
        "payinvoice",
        "--force",
        "--allow_self_payment",
        "--json",
        invoice.to_string()
    )
    .out_json()
    .await?["status"]
        .as_str()
        .context("Missing status field")?
        .to_owned();
    anyhow::ensure!(status == "SUCCEEDED");
    Ok(())
}

pub async fn lnd_wait_invoice_payment(r_hash: String) -> anyhow::Result<()> {
    for _ in 0..60 {
        let result = cmd!(LnCli, "lookupinvoice", &r_hash).out_json().await?;
        let state = result["state"].as_str().context("Missing state field")?;
        if state == "SETTLED" {
            return Ok(());
        }

        fedimint_core::task::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("Timeout waiting for invoice to settle: {r_hash}")
}

pub async fn gateway_pay_invoice(
    prefix: &str,
    gateway_name: &str,
    client: &ClientHandleArc,
    invoice: Bolt11Invoice,
    event_sender: &mpsc::UnboundedSender<MetricEvent>,
    ln_gateway: Option<LightningGateway>,
) -> anyhow::Result<()> {
    let m = fedimint_core::time::now();
    let lightning_module = &client.get_first_module::<LightningClientModule>()?;
    let OutgoingLightningPayment {
        payment_type,
        contract_id: _,
        fee: _,
    } = lightning_module
        .pay_bolt11_invoice(ln_gateway, invoice, ())
        .await?;
    let operation_id = match payment_type {
        fedimint_ln_client::PayType::Internal(_) => bail!("Internal payment not expected"),
        fedimint_ln_client::PayType::Lightning(operation_id) => operation_id,
    };
    let mut updates = lightning_module
        .subscribe_ln_pay(operation_id)
        .await?
        .into_stream();
    while let Some(update) = updates.next().await {
        info!("{prefix} LnPayState update: {update:?}");
        match update {
            LnPayState::Success { preimage: _ } => {
                let elapsed: Duration = m.elapsed()?;
                info!("{prefix} Invoice paid in {elapsed:?}");
                event_sender.send(MetricEvent {
                    name: "gateway_pay_invoice_success".into(),
                    duration: elapsed,
                })?;
                event_sender.send(MetricEvent {
                    name: format!("gateway_{gateway_name}_pay_invoice_success"),
                    duration: elapsed,
                })?;
                break;
            }
            LnPayState::Created
            | LnPayState::Funded { block_height: _ }
            | LnPayState::AwaitingChange => {}
            LnPayState::Canceled => {
                let elapsed: Duration = m.elapsed()?;
                warn!("{prefix} Invoice canceled in {elapsed:?}");
                event_sender.send(MetricEvent {
                    name: "gateway_pay_invoice_canceled".into(),
                    duration: elapsed,
                })?;
                break;
            }
            LnPayState::Refunded { gateway_error } => {
                let elapsed: Duration = m.elapsed()?;
                warn!("{prefix} Invoice refunded due to {gateway_error} in {elapsed:?}");
                event_sender.send(MetricEvent {
                    name: "gateway_pay_invoice_refunded".into(),
                    duration: elapsed,
                })?;
                break;
            }
            LnPayState::WaitingForRefund { error_reason } => {
                warn!("{prefix} Waiting for refund: {error_reason:?}");
            }
            LnPayState::UnexpectedError { error_message } => {
                bail!("Failed to pay invoice: {error_message:?}")
            }
        }
    }
    Ok(())
}

pub async fn ldk_create_invoice(amount: Amount) -> anyhow::Result<Bolt11Invoice> {
    let invoice_string = cmd!(GatewayLdkCli, "lightning", "create-invoice", amount.msats)
        .out_string()
        .await?;
    Ok(Bolt11Invoice::from_str(&invoice_string)?)
}

pub async fn ldk_pay_invoice(invoice: Bolt11Invoice) -> anyhow::Result<()> {
    cmd!(
        GatewayLdkCli,
        "lightning",
        "pay-invoice",
        invoice.to_string()
    )
    .run()
    .await?;
    Ok(())
}

pub async fn ldk_wait_invoice_payment(invoice: &Bolt11Invoice) -> anyhow::Result<()> {
    let gatewayd_version = devimint::util::Gatewayd::version_or_default().await;
    if gatewayd_version < *VERSION_0_7_0_ALPHA {
        return Ok(());
    }

    let status = cmd!(
        GatewayLdkCli,
        "lightning",
        "get-invoice",
        "--payment-hash",
        invoice.payment_hash()
    )
    .out_json()
    .await?["status"]
        .as_str()
        .context("Missing status field")?
        .to_owned();
    if status == "Succeeded" {
        Ok(())
    } else {
        bail!("Got status {status} for invoice {invoice}")
    }
}

pub fn parse_gateway_id(s: &str) -> Result<secp256k1::PublicKey, secp256k1::Error> {
    secp256k1::PublicKey::from_str(s)
}

pub async fn get_note_summary(client: &ClientHandleArc) -> anyhow::Result<TieredCounts> {
    let mint_client = client.get_first_module::<MintClientModule>()?;
    let summary = mint_client
        .get_note_counts_by_denomination(
            &mut client
                .db()
                .begin_transaction_nc()
                .await
                .to_ref_with_prefix_module_id(1)
                .0,
        )
        .await;
    Ok(summary)
}

pub async fn remint_denomination(
    client: &ClientHandleArc,
    denomination: Amount,
    quantity: u16,
) -> anyhow::Result<()> {
    retry(
        format!("remint_{denomination}_{quantity}"),
        aggressive_backoff(),
        || {
            let client = client.clone();
            async move { try_remint_denomination(&client, denomination, quantity).await }
        },
    )
    .await
}

pub async fn try_remint_denomination(
    client: &ClientHandleArc,
    denomination: Amount,
    quantity: u16,
) -> anyhow::Result<()> {
    let mint_client = client.get_first_module::<MintClientModule>()?;
    let mut dbtx = client.db().begin_transaction().await;
    let mut module_transaction = dbtx.to_ref_with_prefix_module_id(mint_client.id).0;
    let mut tx = TransactionBuilder::new();
    let operation_id = OperationId::new_random();
    for _ in 0..quantity {
        let outputs = mint_client
            .create_output(
                &mut module_transaction.to_ref_nc(),
                operation_id,
                1,
                denomination,
            )
            .await
            .into_dyn(mint_client.id);

        tx = tx.with_outputs(outputs);
    }
    drop(module_transaction);
    let operation_meta_gen = |_| ();
    let txid = client
        .finalize_and_submit_transaction(
            operation_id,
            MintCommonInit::KIND.as_str(),
            operation_meta_gen,
            tx,
        )
        .await?
        .txid();
    let tx_subscription = client.transaction_updates(operation_id).await;
    tx_subscription
        .await_tx_accepted(txid)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    dbtx.commit_tx().await;
    for i in 0..quantity {
        let out_point = OutPoint {
            txid,
            out_idx: u64::from(i),
        };
        mint_client
            .await_output_finalized(operation_id, out_point)
            .await?;
    }
    Ok(())
}
