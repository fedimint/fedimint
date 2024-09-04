use std::{ffi, iter};

use clap::Parser;
use fedimint_core::core::OperationId;
use serde::Serialize;

use super::WalletClientModule;
use crate::api::WalletFederationApi;

#[derive(Parser, Serialize)]
enum Opts {
    /// Await a deposit on a given deposit address
    AwaitDeposit {
        operation_id: OperationId,
        #[arg(long, default_value = "1")]
        num: usize,
    },
    /// Returns the Bitcoin RPC kind
    GetBitcoinRpcKind { peer_id: u16 },
    /// Returns the Bitcoin RPC kind and URL, if authenticated
    GetBitcoinRpcConfig,
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
        Opts::GetBitcoinRpcKind { peer_id } => {
            let kind = module
                .module_api
                .fetch_bitcoin_rpc_kind(peer_id.into())
                .await?;

            serde_json::to_value(kind).expect("JSON serialization failed")
        }
        Opts::GetBitcoinRpcConfig => {
            let auth = module
                .admin_auth
                .clone()
                .ok_or(anyhow::anyhow!("Admin auth not set"))?;

            serde_json::to_value(module.module_api.fetch_bitcoin_rpc_config(auth).await?)
                .expect("JSON serialization failed")
        }
    };

    Ok(res)
}
