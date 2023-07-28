use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::vec;

use anyhow::{bail, Context, Result};
use bitcoin::secp256k1;
use devimint::cmd;
use fedimint_client::secret::PlainRootSecretStrategy;
use fedimint_client::sm::OperationId;
use fedimint_client::transaction::TransactionBuilder;
use fedimint_client::{Client, ClientBuilder};
use fedimint_core::api::InviteCode;
use fedimint_core::core::IntoDynInstance;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::CommonModuleGen;
use fedimint_core::{Amount, OutPoint, TieredMulti, TieredSummary};
use fedimint_ln_client::{LightningClientExt, LightningClientGen, LnPayState};
use fedimint_mint_client::{
    MintClientExt, MintClientGen, MintClientModule, MintCommonGen, SpendableNote,
};
use fedimint_wallet_client::WalletClientGen;
use futures::StreamExt;
use lightning_invoice::Invoice;
use tokio::sync::mpsc;
use tracing::info;

use crate::MetricEvent;

pub async fn get_notes_cli(amount: &Amount) -> anyhow::Result<TieredMulti<SpendableNote>> {
    cmd!(FedimintCli, "spend", amount.msats.to_string())
        .out_json()
        .await?["notes"]
        .as_str()
        .map(parse_ecash)
        .transpose()?
        .context("missing notes output")
}

pub async fn try_get_notes_cli(
    amount: &Amount,
    tries: usize,
) -> anyhow::Result<TieredMulti<SpendableNote>> {
    for _ in 0..tries {
        match get_notes_cli(amount).await {
            Ok(notes) => return Ok(notes),
            Err(e) => {
                info!("Failed to get notes from cli: {e}, trying again after a second...");
                fedimint_core::task::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    get_notes_cli(amount).await
}

pub async fn reissue_notes(
    client: &Client,
    notes: TieredMulti<SpendableNote>,
    event_sender: &mpsc::UnboundedSender<MetricEvent>,
) -> anyhow::Result<()> {
    let m = fedimint_core::time::now();
    let operation_id = client.reissue_external_notes(notes, ()).await?;
    let mut updates = client
        .subscribe_reissue_external_notes(operation_id)
        .await?
        .into_stream();
    while let Some(update) = updates.next().await {
        if let fedimint_mint_client::ReissueExternalNotesState::Failed(e) = update {
            return Err(anyhow::Error::msg(format!("Reissue failed: {e}")));
        }
    }
    event_sender.send(MetricEvent {
        name: "reissue_notes".into(),
        duration: m.elapsed()?,
    })?;
    Ok(())
}

pub async fn do_spend_notes(
    client: &Client,
    amount: Amount,
) -> anyhow::Result<(OperationId, TieredMulti<SpendableNote>)> {
    let (operation_id, notes) = client
        .spend_notes(amount, Duration::from_secs(600), ())
        .await?;
    let mut updates = client
        .subscribe_spend_notes(operation_id)
        .await?
        .into_stream();
    if let Some(update) = updates.next().await {
        match update {
            fedimint_mint_client::SpendOOBState::Created
            | fedimint_mint_client::SpendOOBState::Success => {}
            other => {
                return Err(anyhow::Error::msg(format!("Spend failed: {other:?}")));
            }
        }
    }
    Ok((operation_id, notes))
}

pub async fn await_spend_notes_finish(
    client: &Client,
    operation_id: OperationId,
) -> anyhow::Result<()> {
    let mut updates = client
        .subscribe_spend_notes(operation_id)
        .await?
        .into_stream();
    while let Some(update) = updates.next().await {
        info!("SpendOOBState update: {:?}", update);
        match update {
            fedimint_mint_client::SpendOOBState::Created
            | fedimint_mint_client::SpendOOBState::Success => {}
            other => {
                return Err(anyhow::Error::msg(format!("Spend failed: {other:?}")));
            }
        }
    }
    Ok(())
}

pub async fn build_client(
    invite_code: Option<InviteCode>,
    rocksdb: Option<&PathBuf>,
) -> anyhow::Result<Client> {
    let mut client_builder = ClientBuilder::default();
    client_builder.with_module(MintClientGen);
    client_builder.with_module(LightningClientGen);
    client_builder.with_module(WalletClientGen::default());
    client_builder.with_primary_module(1);
    if let Some(invite_code) = invite_code {
        client_builder.with_invite_code(invite_code);
    }
    if let Some(rocksdb) = rocksdb {
        client_builder.with_database(fedimint_rocksdb::RocksDb::open(rocksdb)?)
    } else {
        client_builder.with_database(fedimint_core::db::mem_impl::MemDatabase::new())
    }
    let client = client_builder.build::<PlainRootSecretStrategy>().await?;
    Ok(client)
}

pub fn parse_ecash(s: &str) -> anyhow::Result<TieredMulti<SpendableNote>> {
    let bytes = base64::decode(s)?;
    Ok(Decodable::consensus_decode(
        &mut std::io::Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )?)
}

pub async fn lnd_create_invoice(amount: Amount) -> anyhow::Result<(Invoice, String)> {
    let result = cmd!(LnCli, "addinvoice", "--amt_msat", amount.msats)
        .out_json()
        .await?;
    let invoice = result["payment_request"]
        .as_str()
        .map(Invoice::from_str)
        .transpose()?
        .context("Missing payment_request field")?;
    let r_hash = result["r_hash"]
        .as_str()
        .context("Missing r_hash field")?
        .to_owned();
    Ok((invoice, r_hash))
}

pub async fn lnd_wait_invoice_payment(r_hash: String) -> anyhow::Result<()> {
    for _ in 0..60 {
        let result = cmd!(LnCli, "lookupinvoice", &r_hash).out_json().await?;
        let state = result["state"].as_str().context("Missing state field")?;
        if state == "SETTLED" {
            return Ok(());
        } else {
            fedimint_core::task::sleep(Duration::from_millis(500)).await;
        }
    }
    anyhow::bail!("Timeout waiting for invoice to settle: {r_hash}")
}

pub async fn gateway_pay_invoice(
    client: &Client,
    invoice: Invoice,
    event_sender: &mpsc::UnboundedSender<MetricEvent>,
) -> anyhow::Result<()> {
    let m = fedimint_core::time::now();
    let (pay_type, _) = client.pay_bolt11_invoice(invoice).await?;
    let operation_id = match pay_type {
        fedimint_ln_client::PayType::Internal(_) => bail!("Internal payment not expected"),
        fedimint_ln_client::PayType::Lightning(operation_id) => operation_id,
    };
    let mut updates = client.subscribe_ln_pay(operation_id).await?.into_stream();
    while let Some(update) = updates.next().await {
        info!("LnPayState update: {update:?}");
        match update {
            LnPayState::Success { preimage: _ } => {
                break;
            }
            LnPayState::Created | LnPayState::Funded | LnPayState::AwaitingChange => {}
            other => bail!("Failed to pay invoice: {other:?}"),
        }
    }
    event_sender.send(MetricEvent {
        name: "gateway_pay_invoice".into(),
        duration: m.elapsed()?,
    })?;
    Ok(())
}

pub async fn cln_create_invoice(amount: Amount) -> anyhow::Result<(Invoice, String)> {
    let now = fedimint_core::time::now();
    let random_n: u128 = rand::random();
    let label = format!("label-{now:?}-{random_n}");
    let invoice_string = cmd!(ClnLightningCli, "invoice", amount.msats, &label, &label)
        .out_json()
        .await?["bolt11"]
        .as_str()
        .context("Missing bolt11 field")?
        .to_owned();
    Ok((Invoice::from_str(&invoice_string)?, label))
}

pub async fn cln_wait_invoice_payment(label: &str) -> anyhow::Result<()> {
    let status = cmd!(ClnLightningCli, "waitinvoice", label)
        .out_json()
        .await?["status"]
        .as_str()
        .context("Missing status field")?
        .to_owned();
    if status == "paid" {
        Ok(())
    } else {
        bail!("Got status {status} for invoice {label}")
    }
}

pub async fn switch_default_gateway(client: &Client, gateway_id: &str) -> anyhow::Result<()> {
    let gateway_id = parse_gateway_id(gateway_id)?;
    client.set_active_gateway(&gateway_id).await?;
    Ok(())
}

pub fn parse_gateway_id(s: &str) -> Result<secp256k1::PublicKey, secp256k1::Error> {
    secp256k1::PublicKey::from_str(s)
}

pub async fn get_note_summary(client: &Client) -> anyhow::Result<TieredSummary> {
    let (mint_client, _) = client.get_first_module::<MintClientModule>(&fedimint_mint_client::KIND);
    let summary = mint_client
        .get_wallet_summary(&mut client.db().begin_transaction().await.with_module_prefix(1))
        .await;
    Ok(summary)
}

pub async fn remint_denomination(
    client: &Client,
    denomination: Amount,
    quantity: u16,
) -> anyhow::Result<()> {
    let (mint_client, client_module_instance) =
        client.get_first_module::<MintClientModule>(&fedimint_mint_client::KIND);
    let mut dbtx = client.db().begin_transaction().await;
    let mut module_transaction = dbtx.with_module_prefix(client_module_instance.id);
    let mut tx = TransactionBuilder::new();
    let operation_id = OperationId::new_random();
    for _ in 0..quantity {
        let output = mint_client
            .create_output(&mut module_transaction, operation_id, 1, denomination)
            .await;
        tx = tx.with_output(output.into_dyn(client_module_instance.id));
    }
    drop(module_transaction);
    let operation_meta_gen = |_txid, _outpoint| ();
    let txid = client
        .finalize_and_submit_transaction(
            operation_id,
            MintCommonGen::KIND.as_str(),
            operation_meta_gen,
            tx,
        )
        .await?;
    let tx_subscription = client.transaction_updates(operation_id).await;
    tx_subscription.await_tx_accepted(txid).await?;
    dbtx.commit_tx().await;
    for i in 0..quantity {
        let out_point = OutPoint {
            txid,
            out_idx: i as u64,
        };
        mint_client
            .await_output_finalized(operation_id, out_point)
            .await?;
    }
    Ok(())
}

fn get_command_for_alias(alias: &str, default: &str) -> devimint::util::Command {
    // try to use alias if set
    let cli = std::env::var(alias)
        .map(|s| s.split_whitespace().map(ToOwned::to_owned).collect())
        .unwrap_or_else(|_| vec![default.into()]);
    let mut cmd = tokio::process::Command::new(&cli[0]);
    cmd.args(&cli[1..]);
    devimint::util::Command {
        cmd,
        args_debug: cli,
    }
}

pub struct FedimintCli;
impl FedimintCli {
    pub async fn cmd(self) -> devimint::util::Command {
        get_command_for_alias("FM_MINT_CLIENT", "fedimint-cli")
    }
}

pub struct LnCli;
impl LnCli {
    pub async fn cmd(self) -> devimint::util::Command {
        get_command_for_alias("FM_LNCLI", "lncli")
    }
}

pub struct ClnLightningCli;
impl ClnLightningCli {
    pub async fn cmd(self) -> devimint::util::Command {
        get_command_for_alias("FM_LIGHTNING_CLI", "lightning-cli")
    }
}

pub struct GatewayClnCli;
impl GatewayClnCli {
    pub async fn cmd(self) -> devimint::util::Command {
        get_command_for_alias("FM_GWCLI_CLN", "gateway-cln")
    }
}

pub struct GatewayLndCli;
impl GatewayLndCli {
    pub async fn cmd(self) -> devimint::util::Command {
        get_command_for_alias("FM_GWCLI_LND", "gateway-lnd")
    }
}
