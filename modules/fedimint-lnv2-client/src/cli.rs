use std::{ffi, iter};

use clap::{Parser, Subcommand};
use fedimint_api_client::api::FederationError;
use fedimint_client_module::error::OperationLookupError;
use fedimint_core::core::OperationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use lightning_invoice::Bolt11Invoice;
use serde::Serialize;
use serde_json::Value;

use crate::api::LightningFederationApi;
use crate::{
    Bolt11InvoiceDescription, GenerateLnurlError, LightningClientModule, ListGatewaysError,
    ReceiveError, SelectGatewayError, SendPaymentError,
};

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
    /// Lnurl subcommands
    #[command(subcommand)]
    Lnurl(LnurlOpts),
    /// Gateway subcommands
    #[command(subcommand)]
    Gateways(GatewaysOpts),
}

#[derive(Clone, Subcommand, Serialize)]
enum LnurlOpts {
    /// Generate a new lnurl.
    Generate {
        recurringd: SafeUrl,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewaysOpts {
    /// Update the mapping from lightning node public keys to gateway api
    /// endpoints maintained in the module database to optimise gateway
    /// selection for a given invoice; this command is intended for testing.
    Map,
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
    /// Add a vetted gateway.
    Add { gateway: SafeUrl },
    /// Remove a vetted gateway.
    Remove { gateway: SafeUrl },
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> Result<serde_json::Value, CliCommandError> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2")).chain(args.iter()));

    let value = match opts {
        Opts::Send { gateway, invoice } => {
            json(lightning.send(invoice, gateway, Value::Null).await?)
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
                    gateway,
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
            } => json(lightning.generate_lnurl(recurringd, gateway).await?),
        },
        Opts::Gateways(gateway_opts) => match gateway_opts {
            #[allow(clippy::unit_arg)]
            GatewaysOpts::Map => json(lightning.update_gateway_map().await),
            GatewaysOpts::Select { invoice } => json(lightning.select_gateway(invoice).await?.0),
            GatewaysOpts::List { peer } => json(lightning.list_gateways(peer).await?),
            GatewaysOpts::Add { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(CliCommandError::AdminAuthNotSet)?;

                json(lightning.module_api.add_gateway(auth, gateway).await?)
            }
            GatewaysOpts::Remove { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(CliCommandError::AdminAuthNotSet)?;

                json(lightning.module_api.remove_gateway(auth, gateway).await?)
            }
        },
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}

/// A failure of an `lnv2` module command.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CliCommandError {
    /// The payment could not be started.
    #[error(transparent)]
    Send(#[from] SendPaymentError),

    /// The operation to await could not be looked up.
    #[error(transparent)]
    OperationLookup(#[from] OperationLookupError),

    /// The invoice could not be created.
    #[error(transparent)]
    Receive(#[from] ReceiveError),

    /// The LNURL could not be generated.
    #[error(transparent)]
    GenerateLnurl(#[from] GenerateLnurlError),

    /// No gateway could be selected.
    #[error(transparent)]
    SelectGateway(#[from] SelectGatewayError),

    /// The vetted gateways could not be listed.
    #[error(transparent)]
    ListGateways(#[from] ListGatewaysError),

    /// The federation did not serve an admin request.
    #[error(transparent)]
    Federation(#[from] FederationError),

    /// The client has no admin credentials, which adding or removing a vetted
    /// gateway needs.
    #[error("Admin auth not set")]
    AdminAuthNotSet,
}
