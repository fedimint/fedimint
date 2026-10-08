use std::time::Duration;

use anyhow::{Context, bail, ensure};
use devimint::devfed::DevJitFed;
use devimint::federation::Client;
use devimint::{Gatewayd, cmd};
use fedimint_core::Amount;
use fedimint_core::bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::secp256k1::{Secp256k1, SecretKey};
use fedimint_ln_client::{
    LightningOperationMeta, LightningOperationMetaPay, LightningOperationMetaVariant,
    LightningPaymentOutcome,
};
use fedimint_ln_common::contracts::{ContractId, FundedContract};
use fedimint_ln_common::federation_endpoint_constants::{ACCOUNT_ENDPOINT, BLOCK_COUNT_ENDPOINT};
use fedimint_ln_common::{ContractAccount, KIND};
use fedimint_logging::LOG_TEST;
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use tokio::time::timeout;
use tracing::info;

const PAYMENT_AMOUNT_MSAT: u64 = 100_000;
const REFUND_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) async fn refund_test() -> anyhow::Result<()> {
    Box::pin(
        devimint::run_devfed_test().call(|dev_fed, _process_mgr| async move {
            let fed = dev_fed.fed().await?;
            let gateway = dev_fed.gw_lnd_registered().await?;
            let client = fed.new_joined_client("refused-payment-refund").await?;
            fed.pegin_client(100_000, &client).await?;
            let initial_balance = client.balance().await?;

            // An unreachable recipient makes the gateway fail before any HTLC can settle.
            let invoice = unreachable_invoice()?;
            let first = timeout(REFUND_TIMEOUT, pay(&client, gateway, &invoice))
                .await
                .context("first payment did not fail and refund before its timelock")??;
            ensure!(matches!(first, LightningPaymentOutcome::Failure { .. }));
            let first_payments = payments(&client).await?;
            ensure!(first_payments.len() == 1, "expected one funded payment");
            let first_contract = account(&client, first_payments[0].contract_id).await?;
            ensure!(
                first_contract.amount == Amount::ZERO,
                "first refund was not spent"
            );
            ensure!(
                outgoing_cancelled(&first_contract)?,
                "first contract was not cancelled"
            );
            ensure!(
                client.balance().await? == initial_balance,
                "first refund did not restore ecash"
            );

            // The first refund must complete before this client creates a new contract.
            let retry = timeout(REFUND_TIMEOUT, pay(&client, gateway, &invoice)).await;
            let all_payments = payments(&client).await?;
            ensure!(all_payments.len() == 2, "retry did not fund a new contract");
            ensure!(all_payments[0].contract_id != all_payments[1].contract_id);
            ensure!(all_payments.iter().all(|p| p.invoice == invoice));
            let retry_payment = all_payments
                .iter()
                .find(|p| p.contract_id != first_payments[0].contract_id)
                .context("missing retry contract")?;
            let retry_contract = account(&client, retry_payment.contract_id).await?;
            let block_count = cmd!(client, "dev", "api", "--module", KIND, BLOCK_COUNT_ENDPOINT)
                .out_json()
                .await?["value"]
                .as_u64()
                .context("missing federation block count")?;
            let FundedContract::Outgoing(outgoing) = &retry_contract.contract else {
                bail!("retry did not fund an outgoing contract");
            };
            ensure!(
                block_count < u64::from(outgoing.timelock),
                "refund reached the timelock"
            );

            if retry.is_err() {
                ensure!(retry_contract.amount > Amount::ZERO);
                ensure!(!outgoing.cancelled);
                bail!(
                    "same-invoice retry remains funded and uncancelled before refund height {}",
                    outgoing.timelock
                );
            }
            let retry = retry.context("retry timed out")??;
            ensure!(matches!(retry, LightningPaymentOutcome::Failure { .. }));
            ensure!(outgoing.cancelled, "refused retry was not cancelled");
            ensure!(
                retry_contract.amount == Amount::ZERO,
                "refused retry was not refunded"
            );
            ensure!(
                client.balance().await? == initial_balance,
                "retry refund did not restore ecash"
            );

            refund_paid_invoice(&dev_fed, &client, gateway).await?;
            info!(target: LOG_TEST, "refused same-invoice contract refunded before its timelock");
            Ok(())
        }),
    )
    .await
}

async fn refund_paid_invoice(
    dev_fed: &DevJitFed,
    payer: &Client,
    gateway: &Gatewayd,
) -> anyhow::Result<()> {
    let fed = dev_fed.fed().await?;
    let recipient = dev_fed.gw_ldk_connected().await?;
    let invoice = recipient
        .client()
        .create_invoice(PAYMENT_AMOUNT_MSAT)
        .await?;
    let outcome = timeout(REFUND_TIMEOUT, pay(payer, gateway, &invoice))
        .await
        .context("fresh invoice payment timed out")??;
    ensure!(matches!(outcome, LightningPaymentOutcome::Success { .. }));
    let federation_id = fed.calculate_federation_id().clone();
    let gateway_balance = gateway
        .client()
        .ecash_balance(federation_id.clone())
        .await?;

    // A separate client has no local record of this invoice's successful payment.
    let retry_client = fed.new_joined_client("paid-invoice-refund").await?;
    fed.pegin_client(100_000, &retry_client).await?;
    let initial_balance = retry_client.balance().await?;
    let outcome = timeout(REFUND_TIMEOUT, pay(&retry_client, gateway, &invoice))
        .await
        .context("paid-invoice retry did not refund promptly")??;
    ensure!(matches!(outcome, LightningPaymentOutcome::Failure { .. }));
    let operations = payments(&retry_client).await?;
    ensure!(operations.len() == 1);
    let contract = account(&retry_client, operations[0].contract_id).await?;
    ensure!(outgoing_cancelled(&contract)?);
    ensure!(contract.amount == Amount::ZERO);
    ensure!(retry_client.balance().await? == initial_balance);
    ensure!(
        gateway.client().ecash_balance(federation_id).await? == gateway_balance,
        "refused contract must not pay the gateway twice"
    );
    Ok(())
}

fn unreachable_invoice() -> anyhow::Result<Bolt11Invoice> {
    let secret = SecretKey::from_slice(&[1; 32])?;
    let secp = Secp256k1::new();
    Ok(InvoiceBuilder::new(Currency::Regtest)
        .description("unreachable recipient".to_owned())
        .payment_hash(sha256::Hash::hash(b"refused-payment-refund"))
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .payment_secret(PaymentSecret([2; 32]))
        .amount_milli_satoshis(PAYMENT_AMOUNT_MSAT)
        .build_signed(|message| secp.sign_ecdsa_recoverable(message, &secret))?)
}

async fn pay(
    client: &Client,
    gateway: &Gatewayd,
    invoice: &Bolt11Invoice,
) -> anyhow::Result<LightningPaymentOutcome> {
    let value = cmd!(
        client,
        "module",
        KIND,
        "pay",
        invoice,
        "--gateway-id",
        &gateway.gateway_id
    )
    .kill_on_drop(true)
    .out_json()
    .await?;
    Ok(serde_json::from_value(value)?)
}

async fn payments(client: &Client) -> anyhow::Result<Vec<LightningOperationMetaPay>> {
    let value = cmd!(client, "list-operations", "--limit", "100")
        .out_json()
        .await?;
    let mut payments = Vec::new();
    for operation in value["operations"]
        .as_array()
        .context("missing operations")?
    {
        if operation["operation_kind"].as_str() != Some(KIND.as_str()) {
            continue;
        }
        let meta: LightningOperationMeta =
            serde_json::from_value(operation["operation_meta"].clone())?;
        if let LightningOperationMetaVariant::Pay(payment) = meta.variant {
            payments.push(payment);
        }
    }
    Ok(payments)
}

async fn account(client: &Client, contract_id: ContractId) -> anyhow::Result<ContractAccount> {
    let value = cmd!(
        client,
        "dev",
        "api",
        "--module",
        KIND,
        ACCOUNT_ENDPOINT,
        serde_json::to_string(&contract_id)?
    )
    .out_json()
    .await?;
    serde_json::from_value::<Option<ContractAccount>>(value["value"].clone())?
        .context("funded contract is missing")
}

fn outgoing_cancelled(account: &ContractAccount) -> anyhow::Result<bool> {
    match &account.contract {
        FundedContract::Outgoing(contract) => Ok(contract.cancelled),
        FundedContract::Incoming(_) => bail!("expected an outgoing contract"),
    }
}
