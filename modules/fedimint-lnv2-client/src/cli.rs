use std::{ffi, iter};

use bitcoin30::secp256k1::PublicKey;
use clap::{Parser, Subcommand};
use fedimint_core::core::OperationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use lightning_invoice::Bolt11Invoice;
use serde::Serialize;
use serde_json::Value;

use crate::api::LnFederationApi;
use crate::{Bolt11InvoiceDescription, LightningClientModule};

#[derive(Parser, Serialize)]
enum Opts {
    /// Pay an invoice. For  testing  you can optionally specify a gateway to
    /// route with, otherwise a gateway will be selected automatically.
    Send {
        invoice: Bolt11Invoice,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the send operation.
    AwaitSend { operation_id: OperationId },
    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a gateway will be selected
    /// automatically.
    Receive {
        amount: Amount,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the receive operation.
    AwaitReceive { operation_id: OperationId },
    /// Gateway subcommands
    #[command(subcommand)]
    Gateway(GatewayOpts),
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewayOpts {
    /// Select an online vetted gateway; this command is intended for testing.
    Select {
        #[arg(long)]
        invoice: Option<Bolt11Invoice>,
    },
    /// List all vetted gateways.
    List {
        #[arg(long)]
        peer: Option<PeerId>,
    },
    /// Manually add a gateway to the client's cache
    Add {
        #[arg(long)]
        gateway_key: PublicKey,

        #[arg(long)]
        gateway: SafeUrl,
    },
    /// Manually delete a gateway from the client's cache
    Delete {
        #[arg(long)]
        gateway: SafeUrl,
    },
    /// Register a vetted gateway.
    Register { gateway: SafeUrl },
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
            json(lightning.send(invoice, gateway, Value::Null).await?)
        }
        Opts::AwaitSend { operation_id } => json(lightning.await_send(operation_id).await?),
        Opts::Receive { amount, gateway } => json(
            lightning
                .receive(
                    amount,
                    3600,
                    Bolt11InvoiceDescription::Direct(String::new()),
                    gateway,
                    Value::Null,
                )
                .await?,
        ),
        Opts::AwaitReceive { operation_id } => json(lightning.await_receive(operation_id).await?),
        Opts::Gateway(gateway_opts) => match gateway_opts {
            GatewayOpts::Add {
                gateway_key,
                gateway,
            } => json(lightning.add_gateway(gateway_key, gateway).await),
            GatewayOpts::Delete { gateway } => json(lightning.delete_gateway(gateway).await),
            GatewayOpts::Select { invoice } => json(lightning.select_gateway(invoice).await?.0),
            GatewayOpts::List { peer } => match peer {
                Some(peer) => json(lightning.module_api.gateways_from_peer(peer).await?),
                None => json(lightning.list_all_gateways().await?),
            },
            GatewayOpts::Register { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(anyhow::anyhow!("Admin auth not set"))?;

                json(lightning.module_api.register_gateway(auth, gateway).await?)
            }
            GatewayOpts::Remove { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(anyhow::anyhow!("Admin auth not set"))?;

                json(
                    lightning
                        .module_api
                        .remove_registered_gateway(auth, gateway)
                        .await?,
                )
            }
        },
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
