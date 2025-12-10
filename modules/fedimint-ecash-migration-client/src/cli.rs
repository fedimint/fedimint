use std::path::PathBuf;
use std::{ffi, iter};

use anyhow::Context as _;
use clap::Parser;
use fedimint_core::Amount;
use fedimint_core::core::OperationId;
use fedimint_ecash_migration_common::TransferId;
use futures::StreamExt;
use serde::Serialize;

use crate::EcashMigrationClientModule;
use crate::states::{FundTransferState, RegisterTransferState};

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

    /// Upload the origin federation's keyset to associate with a transfer.
    ///
    /// This must be done after the transfer is registered but before
    /// activation.
    UploadKeyset {
        /// The transfer ID to associate the keyset with.
        transfer_id: TransferId,

        /// Path to the JSON file containing the origin federation's client
        /// config. This contains the public keys needed to verify origin
        /// federation ecash.
        ///
        /// The config can be dumped in JSON format using `fedimint-cli
        /// --data-dir <data-dir> config` on the origin federation.
        #[arg(long)]
        origin_config: PathBuf,
    },

    /// Upload the spend book entries in batches to the destination federation.
    ///
    /// This must be done after the transfer is registered but before
    /// activation. The spend book can be uploaded in multiple sessions; the
    /// server tracks progress.
    UploadSpendBook {
        /// The transfer ID to upload the spend book for.
        transfer_id: TransferId,

        /// Path to a file containing the sorted spend book entries from the
        /// origin federation. Each line should contain a hex-encoded nonce
        /// that has been spent in the origin federation.
        #[arg(long)]
        spend_book: PathBuf,

        /// Number of entries to upload per batch.
        #[arg(long, default_value = "10000")]
        batch_size: usize,
    },

    /// Fund an existing liability transfer with Bitcoin.
    ///
    /// This deposits Bitcoin into the transfer contract, making it available
    /// for redemption of origin federation ecash.
    FundTransfer {
        /// The transfer ID to fund.
        #[arg(long)]
        transfer_id: TransferId,

        /// Amount to deposit in millisatoshis.
        #[arg(long)]
        amount: Amount,
    },

    /// Await completion of a previously started fund transfer.
    ///
    /// Use this to resume waiting for a fund transfer that was interrupted
    /// (e.g., due to a client crash) before it completed.
    AwaitFundTransfer {
        /// The operation ID returned when the fund transfer was started.
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
        Opts::UploadKeyset {
            transfer_id,
            origin_config,
        } => upload_keyset(module, transfer_id, origin_config).await,
        Opts::UploadSpendBook {
            transfer_id,
            spend_book,
            batch_size,
        } => upload_spend_book(module, transfer_id, spend_book, batch_size).await,
        Opts::FundTransfer {
            transfer_id,
            amount,
        } => fund_transfer(module, transfer_id, amount).await,
        Opts::AwaitFundTransfer { operation_id } => await_fund_transfer(module, operation_id).await,
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

async fn upload_keyset(
    module: &EcashMigrationClientModule,
    transfer_id: TransferId,
    origin_config_path: PathBuf,
) -> anyhow::Result<serde_json::Value> {
    module
        .upload_keyset(transfer_id, &origin_config_path)
        .await
        .context("Failed to upload keyset")?;

    Ok(serde_json::json!({
        "transfer_id": transfer_id,
    }))
}

async fn upload_spend_book(
    module: &EcashMigrationClientModule,
    transfer_id: TransferId,
    spend_book_path: PathBuf,
    batch_size: usize,
) -> anyhow::Result<serde_json::Value> {
    let progress = module
        .upload_spend_book(transfer_id, &spend_book_path, batch_size)
        .await
        .context("Failed to upload spend book")?;

    Ok(serde_json::json!({
        "transfer_id": transfer_id,
        "total_uploaded": progress.total_uploaded,
        "batches_uploaded": progress.batches_uploaded,
    }))
}

async fn fund_transfer(
    module: &EcashMigrationClientModule,
    transfer_id: TransferId,
    amount: Amount,
) -> anyhow::Result<serde_json::Value> {
    let operation_id = module
        .fund_transfer(transfer_id, amount)
        .await
        .context("Failed to fund transfer")?;

    await_fund_transfer(module, operation_id).await
}

async fn await_fund_transfer(
    module: &EcashMigrationClientModule,
    operation_id: OperationId,
) -> anyhow::Result<serde_json::Value> {
    let mut updates = module
        .subscribe_fund_transfer(operation_id)
        .await
        .context("Failed to subscribe to fund transfer updates")?
        .into_stream();

    let mut result = None;
    let mut error = None;

    while let Some(state) = updates.next().await {
        match state {
            FundTransferState::Success {
                transfer_id,
                amount,
            } => {
                result = Some((transfer_id, amount));
                break;
            }
            FundTransferState::Failed { error: e } => {
                error = Some(e);
                break;
            }
            _ => {}
        }
    }

    if let Some(error) = error {
        anyhow::bail!("Fund transfer failed: {error}");
    }

    let (transfer_id, amount) = result.context("Fund transfer did not complete successfully")?;

    Ok(serde_json::json!({
        "operation_id": operation_id,
        "transfer_id": transfer_id,
        "amount_msat": amount.msats,
    }))
}
