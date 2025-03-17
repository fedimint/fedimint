use std::collections::BTreeMap;
use std::time::UNIX_EPOCH;
use std::{ffi, iter};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use fedimint_core::Amount;
use fedimint_core::core::OperationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use futures::StreamExt;
use lightning_invoice::{Bolt11InvoiceDescription, Description};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info};

use crate::recurring::{PaymentCodeRootKey, RecurringPaymentProtocol};
use crate::{
    LightningOperationMeta, LightningOperationMetaVariant, LnReceiveState, OutgoingLightningPayment,
};

#[derive(Parser, Serialize)]
enum Opts {
    /// Create a lightning invoice to receive payment via gateway
    Invoice {
        amount: Amount,
        #[clap(long, default_value = "")]
        description: String,
        #[clap(long)]
        expiry_time: Option<u64>,
        #[clap(long)]
        gateway_id: Option<PublicKey>,
        #[clap(long, default_value = "false")]
        force_internal: bool,
    },
    /// Pay a lightning invoice or lnurl via a gateway
    Pay {
        /// Lightning invoice or lnurl
        payment_info: String,
        /// Amount to pay, used for lnurl
        #[clap(long)]
        amount: Option<Amount>,
        /// Invoice comment/description, used on lnurl
        #[clap(long)]
        lnurl_comment: Option<String>,
        /// Will return immediately after funding the payment
        #[clap(long, action)]
        finish_in_background: bool,
        #[clap(long)]
        gateway_id: Option<PublicKey>,
        #[clap(long, default_value = "false")]
        force_internal: bool,
    },
    /// Register and manage LNURLs
    #[clap(subcommand)]
    Lnurl(LnurlCommands),
}

#[derive(Subcommand, Serialize)]
enum LnurlCommands {
    /// Register a new LNURL payment code with a specific LNURL server
    Register {
        /// The LNURL server to register with
        server_url: SafeUrl,
        /// Set LNURL meta data, see LUD-06 for more details on the format
        #[clap(long)]
        meta: Option<String>,
        ///Shrthand for setting the short description in the LNURL meta data
        #[clap(long, default_value = "Fedimint LNURL Pay")]
        description: String,
    },
    /// List all LNURLs registered
    List,
    /// List all invoices generated for a LNURL
    Invoices { payment_code_idx: u64 },
    /// Await a LNURL-triggered lightning receive operation to complete
    AwaitReceive {
        /// The operation ID of the receive operation to await
        operation_id: OperationId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LnInvoiceResponse {
    pub operation_id: OperationId,
    pub invoice: String,
}

pub(crate) async fn handle_cli_command(
    module: &super::LightningClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("meta")).chain(args.iter()));

    Ok(match opts {
        Opts::Invoice {
            amount,
            description,
            expiry_time,
            gateway_id,
            force_internal,
        } => {
            let ln_gateway = module.get_gateway(gateway_id, force_internal).await?;

            let desc = Description::new(description)?;
            let (operation_id, invoice, _) = module
                .create_bolt11_invoice(
                    amount,
                    Bolt11InvoiceDescription::Direct(&desc),
                    expiry_time,
                    (),
                    ln_gateway,
                )
                .await?;
            serde_json::to_value(LnInvoiceResponse {
                operation_id,
                invoice: invoice.to_string(),
            })
            .expect("Can't fail")
        }
        Opts::Pay {
            payment_info,
            amount,
            finish_in_background,
            lnurl_comment,
            gateway_id,
            force_internal,
        } => {
            let bolt11 = crate::get_invoice(&payment_info, amount, lnurl_comment).await?;
            info!("Paying invoice: {bolt11}");
            let ln_gateway = module.get_gateway(gateway_id, force_internal).await?;

            let OutgoingLightningPayment {
                payment_type,
                contract_id,
                fee,
            } = module.pay_bolt11_invoice(ln_gateway, bolt11, ()).await?;
            let operation_id = payment_type.operation_id();
            info!(
                "Gateway fee: {fee}, payment operation id: {}",
                operation_id.fmt_short()
            );
            if finish_in_background {
                module
                    .wait_for_ln_payment(payment_type, contract_id, true)
                    .await?;
                info!("Payment will finish in background, use await-ln-pay to get the result");
                serde_json::json! {
                    {
                        "operation_id": operation_id,
                        "payment_type": payment_type.payment_type(),
                        "contract_id": contract_id,
                        "fee": fee,
                    }
                }
            } else {
                module
                    .wait_for_ln_payment(payment_type, contract_id, false)
                    .await?
                    .context("expected a response")?
            }
        }
        Opts::Lnurl(LnurlCommands::Register {
            server_url,
            meta,
            description,
        }) => {
            let meta = meta.unwrap_or_else(|| {
                serde_json::to_string(&json!([["text/plain", description]]))
                    .expect("serialization can't fail")
            });
            let recurring_payment_code = module
                .register_recurring_payment_code(RecurringPaymentProtocol::LNURL, server_url, &meta)
                .await?;
            json!({
                "lnurl": recurring_payment_code.code,
            })
        }
        Opts::Lnurl(LnurlCommands::List) => {
            let codes: BTreeMap<u64, serde_json::Value> = module
                .list_recurring_payment_codes()
                .await
                .into_iter()
                .map(|(idx, code)| {
                    let root_public_key = PaymentCodeRootKey(code.root_keypair.public_key());
                    let recurring_payment_code_id = root_public_key.to_payment_code_id();
                    let creation_timestamp = code
                        .creation_time
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs();
                    let code_json = json!({
                        "lnurl": code.code,
                        // TODO: use time_to_iso8601
                        "creation_timestamp": creation_timestamp,
                        "root_public_key": root_public_key,
                        "recurring_payment_code_id": recurring_payment_code_id,
                        "recurringd_api": code.recurringd_api,
                        "last_derivation_index": code.last_derivation_index,
                    });
                    (idx, code_json)
                })
                .collect();

            json!({
                "codes": codes,
            })
        }
        Opts::Lnurl(LnurlCommands::Invoices { payment_code_idx }) => {
            let invoices = module
                .list_recurring_payment_code_invoices(payment_code_idx)
                .await
                .context("Unknown payment code index")?
                .into_iter()
                .map(|(idx, operation_id)| {
                    let invoice = json!({
                        "operation_id": operation_id,
                    });
                    (idx, invoice)
                })
                .collect::<BTreeMap<_, _>>();
            json!({
                "invoices": invoices,
            })
        }
        Opts::Lnurl(LnurlCommands::AwaitReceive { operation_id }) => {
            let LightningOperationMetaVariant::RecurringPaymentReceive(operation_meta) = module
                .client_ctx
                .get_operation(operation_id)
                .await?
                .meta::<LightningOperationMeta>()
                .variant
            else {
                bail!("Operation is not a recurring lightning receive")
            };
            let mut stream = module
                .subscribe_ln_recurring_receive(operation_id)
                .await?
                .into_stream();
            while let Some(update) = stream.next().await {
                debug!(?update, "Await invoice state update");
                match update {
                    LnReceiveState::Claimed => {
                        let amount_msat = operation_meta.invoice.amount_milli_satoshis();
                        return Ok(json!({
                            "payment_code_id": operation_meta.payment_code_id,
                            "invoice": operation_meta.invoice,
                            "amount_msat": amount_msat,
                        }));
                    }
                    LnReceiveState::Canceled { reason } => {
                        return Err(reason.into());
                    }
                    _ => {}
                }
            }
            unreachable!("Stream should not end without an outcome");
        }
    })
}
