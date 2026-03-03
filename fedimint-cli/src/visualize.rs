//! Debug visualization commands for client internals.
//!
//! Thin CLI wrappers around the data-fetching and rendering provided by
//! [`fedimint_client::visualize`] and [`fedimint_mint_client::visualize`].

use fedimint_client::Client;
use fedimint_client::visualize::{OperationsVisOutput, TransactionsVisOutput};
use fedimint_core::core::OperationId;
use fedimint_mint_client::visualize::get_notes_vis;

use crate::{CliError, CliResultExt};

pub async fn cmd_notes(client: &Client, limit: Option<usize>) -> Result<(), CliError> {
    eprintln!("E-cash notes with creation and spending provenance.");
    eprintln!("Each note shows nonce, blind_nonce, and amount (in msats).");
    eprintln!("  created: timestamp, operation id, and tx output that issued the note");
    eprintln!("  spent:   timestamp, operation id, and tx input that consumed the note");
    eprintln!("Notes without a 'spent' line are still in the wallet.");
    eprintln!();

    let output = get_notes_vis(client, limit).await;
    print!("{output}");

    Ok(())
}

pub async fn cmd_transactions(
    client: &Client,
    operation_id: Option<OperationId>,
    limit: Option<usize>,
) -> Result<(), CliError> {
    eprintln!("Transactions with their inputs and outputs, grouped by operation.");
    eprintln!("Each tx shows its status (accepted/rejected/pending) and timestamp.");
    eprintln!("Inputs and outputs show module id, module kind, and Display of the item.");
    eprintln!();

    let data = client
        .get_transactions_vis(operation_id, limit)
        .await
        .map_err_cli()?;
    print!("{}", TransactionsVisOutput(data));

    Ok(())
}

pub async fn cmd_operations(
    client: &Client,
    operation_id: Option<OperationId>,
    limit: Option<usize>,
) -> Result<(), CliError> {
    eprintln!("Operations with their state machines, sorted by creation time.");
    eprintln!("Each operation shows timestamp, op id, module type, and outcome status.");
    eprintln!("Each state shows [done/active], timestamp, duration, module kind, and details.");
    eprintln!();

    let data = client
        .get_operations_vis(operation_id, limit)
        .await
        .map_err_cli()?;
    print!("{}", OperationsVisOutput(data));

    Ok(())
}
