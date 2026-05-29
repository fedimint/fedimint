use std::{ffi, iter};

use clap::{Parser, Subcommand};
use fedimint_core::core::OperationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use lightning_invoice::Bolt11Invoice;
use serde::Serialize;
use serde_json::Value;

use crate::api::LightningFederationApi;
use crate::{Bolt11InvoiceDescription, LightningClientModule};

#[derive(Parser, Serialize)]
enum Opts {
    /// Pay an invoice via the specified gateway.
    Send {
        invoice: Bolt11Invoice,
        #[arg(long)]
        gateway: SafeUrl,
    },
    /// Await the final state of the send operation.
    AwaitSend { operation_id: OperationId },
    /// Request an invoice from the specified gateway.
    Receive {
        amount: Amount,
        #[arg(long)]
        gateway: SafeUrl,
    },
    /// Await the final state of the receive operation.
    AwaitReceive { operation_id: OperationId },
    /// Lnurl subcommands
    #[command(subcommand)]
    Lnurl(LnurlOpts),
    /// Gateway subcommands
    #[command(subcommand)]
    Gateways(GatewaysOpts),
}

#[derive(Clone, Subcommand, Serialize)]
enum LnurlOpts {
    /// Generate a new lnurl pinned to the specified gateway.
    Generate {
        recurringd: SafeUrl,
        #[arg(long)]
        gateway: SafeUrl,
    },
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewaysOpts {
    /// Refresh the gateway cache and pick an online vetted gateway. If
    /// `--invoice` is set and one of the cached gateways is the payee,
    /// that gateway is returned so a subsequent `send` can settle as a
    /// direct ecash swap.
    Select {
        #[arg(long)]
        invoice: Option<Bolt11Invoice>,
    },
    /// List all vetted gateways.
    List {
        #[arg(long)]
        peer: Option<PeerId>,
    },
    /// Add a vetted gateway.
    Add { gateway: SafeUrl },
    /// Remove a vetted gateway.
    Remove { gateway: SafeUrl },
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2")).chain(args.iter()));

    let value = match opts {
        Opts::Send { gateway, invoice } => {
            json(lightning.send(invoice, Some(gateway), Value::Null).await?)
        }
        Opts::AwaitSend { operation_id } => json(
            lightning
                .await_final_send_operation_state(operation_id)
                .await?,
        ),
        Opts::Receive { amount, gateway } => json(
            lightning
                .receive(
                    amount,
                    3600,
                    Bolt11InvoiceDescription::Direct(String::new()),
                    Some(gateway),
                    Value::Null,
                )
                .await?,
        ),
        Opts::AwaitReceive { operation_id } => json(
            lightning
                .await_final_receive_operation_state(operation_id)
                .await?,
        ),
        Opts::Lnurl(lnurl_opts) => match lnurl_opts {
            LnurlOpts::Generate {
                recurringd,
                gateway,
            } => json(lightning.generate_lnurl(&recurringd, Some(gateway)).await?),
        },
        Opts::Gateways(gateway_opts) => match gateway_opts {
            GatewaysOpts::Select { invoice } => {
                json(lightning.select_gateway(invoice.as_ref(), true).await?.0)
            }
            GatewaysOpts::List { peer } => json(lightning.list_gateways(peer).await?),
            GatewaysOpts::Add { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(anyhow::anyhow!("Admin auth not set"))?;

                json(lightning.module_api.add_gateway(auth, gateway).await?)
            }
            GatewaysOpts::Remove { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(anyhow::anyhow!("Admin auth not set"))?;

                json(lightning.module_api.remove_gateway(auth, gateway).await?)
            }
        },
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
