use std::{ffi, iter};

use clap::{Parser, Subcommand};
use fedimint_core::core::OperationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use lightning_invoice::Bolt11Invoice;
use serde::Serialize;
use serde_json::Value;

use crate::api::LnFederationApi;
use crate::LightningClientModule;

#[derive(Parser, Serialize)]
enum Opts {
    /// Pay an invoice
    Send {
        gateway: SafeUrl,
        invoice: Bolt11Invoice,
    },
    /// Await the final state of the send operation
    AwaitSend { operation_id: OperationId },
    /// Request an invoice
    Receive { gateway: SafeUrl, amount: Amount },
    /// Await the final state of the receive operation
    AwaitReceive { operation_id: OperationId },
    /// Gateway subcommands
    #[command(subcommand)]
    Gateway(GatewayOpts),
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewayOpts {
    /// List vetted gateways
    List { peer: Option<PeerId> },
    /// Add a vetted gateway
    Add { gateway: SafeUrl },
    /// Remove a vetted gateway
    Remove { gateway: SafeUrl },
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2")).chain(args.iter()));

    let value = match opts {
        Opts::Send { gateway, invoice } => json(lightning.send(gateway, invoice).await?),
        Opts::AwaitSend { operation_id } => json(lightning.await_send(operation_id).await?),
        Opts::Receive { gateway, amount } => json(lightning.receive(gateway, amount).await?),
        Opts::AwaitReceive { operation_id } => json(lightning.await_receive(operation_id).await?),
        Opts::Gateway(gateway_opts) => match gateway_opts {
            GatewayOpts::List { peer } => match peer {
                Some(peer) => json(lightning.module_api.gateways_from_peer(peer).await?),
                None => json(lightning.module_api.gateways().await?),
            },
            GatewayOpts::Add { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(anyhow::anyhow!("Admin auth not set"))?;

                json(lightning.module_api.add_gateway(auth, gateway).await?)
            }
            GatewayOpts::Remove { gateway } => {
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
