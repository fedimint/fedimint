use std::{ffi, iter};

use clap::Parser;
use fedimint_core::core::OperationId;
use serde::Serialize;

use super::WalletClientModule;

#[derive(Parser, Serialize)]
enum Opts {
    /// Await a deposit on a given deposit address
    AwaitDeposit {
        operation_id: OperationId,
        #[arg(long, default_value = "1")]
        num: usize,
    },
}

pub(crate) async fn handle_cli_command(
    module: &WalletClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("wallet")).chain(args.iter()));

    let res = match opts {
        Opts::AwaitDeposit { operation_id, num } => {
            module
                .await_num_deposit_by_operation_id(operation_id, num)
                .await?;
            serde_json::Value::Null
        }
    };

    Ok(res)
}
