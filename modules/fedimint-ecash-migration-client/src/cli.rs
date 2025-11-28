use std::path::PathBuf;
use std::{ffi, iter};

use anyhow::Context as _;
use clap::Parser;
use fedimint_core::core::OperationId;
use futures::StreamExt;
use serde::Serialize;

use crate::EcashMigrationClientModule;
use crate::states::RegisterTransferState;

#[derive(Parser, Serialize)]
enum Opts {
    /// Register a new liability transfer with the federation.
    ///
    /// This creates a transfer request that allows ecash from another
    /// federation to be redeemed in this federation after the transfer
    /// is funded and activated.
    RegisterTransfer {
        /// Path to the JSON file containing the origin federation's mint client
        /// config. This contains the public keys needed to verify origin
        /// federation ecash.
        ///
        /// The config can be dumped in JSON format using `fedimint-cli
        /// --data-dir <data-dir> config` on the origin federation.
        #[arg(long)]
        origin_config: PathBuf,

        /// Path to a file containing the sorted spend book entries from the
        /// origin federation. Each line should contain a hex-encoded nonce
        /// that has been spent in the origin federation.
        #[arg(long)]
        spend_book: PathBuf,
    },

    /// Await completion of a previously started transfer registration.
    ///
    /// Use this to resume waiting for a transfer registration that was
    /// interrupted (e.g., due to a client crash) before it completed.
    AwaitRegisterTransfer {
        /// The operation ID returned when the transfer registration was
        /// started.
        operation_id: OperationId,
    },
}

pub(crate) async fn handle_cli_command(
    module: &EcashMigrationClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts =
        Opts::parse_from(iter::once(&ffi::OsString::from("ecash-migration")).chain(args.iter()));

    match opts {
        Opts::RegisterTransfer {
            origin_config,
            spend_book,
        } => register_transfer(module, origin_config, spend_book).await,
        Opts::AwaitRegisterTransfer { operation_id } => {
            await_register_transfer(module, operation_id).await
        }
    }
}

async fn register_transfer(
    module: &EcashMigrationClientModule,
    origin_config_path: PathBuf,
    spend_book_path: PathBuf,
) -> anyhow::Result<serde_json::Value> {
    // Register the transfer
    let operation_id = module
        .register_transfer(origin_config_path, spend_book_path)
        .await
        .context("Failed to register transfer")?;

    await_register_transfer(module, operation_id).await
}

async fn await_register_transfer(
    module: &EcashMigrationClientModule,
    operation_id: OperationId,
) -> anyhow::Result<serde_json::Value> {
    // Subscribe and wait for completion
    let mut updates = module
        .subscribe_register_transfer(operation_id)
        .await
        .context("Failed to subscribe to transfer updates")?
        .into_stream();

    let mut transfer_id = None;
    let mut error = None;

    while let Some(state) = updates.next().await {
        match state {
            RegisterTransferState::Success { transfer_id: id } => {
                transfer_id = Some(id);
                break;
            }
            RegisterTransferState::Failed { error: e } => {
                error = Some(e);
                break;
            }
            _ => {}
        }
    }

    if let Some(error) = error {
        anyhow::bail!("Transfer registration failed: {error}");
    }

    let transfer_id = transfer_id.context("Transfer registration did not complete successfully")?;

    Ok(serde_json::json!({
        "operation_id": operation_id,
        "transfer_id": transfer_id,
    }))
}
