use std::{ffi, iter};

use anyhow::Context as _;
use clap::Parser;
use fedimint_core::Amount;
use fedimint_core::core::OperationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use lightning_invoice::{Bolt11InvoiceDescription, Description};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::OutgoingLightningPayment;
use crate::recurring::RecurringPaymentProtocol;

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
    RegisterLNURL {
        server_url: SafeUrl,
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
        Opts::RegisterLNURL { server_url } => {
            let recurring_payment_code = module
                .register_recurring_payment_code(RecurringPaymentProtocol::LNURL, server_url)
                .await?;
            json!({
                "lnurl": recurring_payment_code.code,
            })
        }
    })
}
