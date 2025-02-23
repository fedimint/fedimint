use std::str::FromStr as _;
use std::{ffi, iter};

use anyhow::bail;
use bitcoin::address::NetworkUnchecked;
use clap::Parser;
use fedimint_core::core::OperationId;
use serde::Serialize;

use super::WalletClientModule;
use crate::api::WalletFederationApi;
use crate::client_db::TweakIdx;

#[derive(Parser, Serialize)]
enum Opts {
    /// Await a deposit on a given deposit address
    AwaitDeposit {
        addr: Option<String>,
        #[arg(long)]
        operation_id: Option<OperationId>,
        #[arg(long)]
        tweak_idx: Option<TweakIdx>,
        /// Await more than just one deposit
        #[arg(long, default_value = "1")]
        num: usize,
    },
    GetConsensusBlockCount,
    /// Returns the Bitcoin RPC kind
    GetBitcoinRpcKind {
        peer_id: u16,
    },
    /// Returns the Bitcoin RPC kind and URL, if authenticated
    GetBitcoinRpcConfig,

    NewDepositAddress,
    /// Trigger wallet address check (in the background)
    RecheckDepositAddress {
        addr: Option<bitcoin::Address<NetworkUnchecked>>,
        #[arg(long)]
        operation_id: Option<OperationId>,
        #[arg(long)]
        tweak_idx: Option<TweakIdx>,
    },
}

pub(crate) async fn handle_cli_command(
    module: &WalletClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("wallet")).chain(args.iter()));

    let res = match opts {
        Opts::AwaitDeposit {
            operation_id,
            num,
            addr,
            tweak_idx,
        } => {
            if u32::from(addr.is_some())
                + u32::from(operation_id.is_some())
                + u32::from(tweak_idx.is_some())
                != 1
            {
                bail!("One and only one of the selector arguments must be set")
            }
            if let Some(tweak_idx) = tweak_idx {
                module.await_num_deposits(tweak_idx, num).await?;
            } else if let Some(operation_id) = operation_id {
                module
                    .await_num_deposits_by_operation_id(operation_id, num)
                    .await?;
            } else if let Some(addr) = addr {
                if addr.len() == 64 {
                    eprintln!(
                        "Interpreting addr as an operation_id for backward compatibility. Use `--operation-id` from now on."
                    );
                    let operation_id = OperationId::from_str(&addr)?;
                    module
                        .await_num_deposits_by_operation_id(operation_id, num)
                        .await?;
                } else {
                    let addr = bitcoin::Address::from_str(&addr)?;
                    module.await_num_deposits_by_address(addr, num).await?;
                }
            } else {
                unreachable!()
            }
            serde_json::Value::Bool(true)
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
        Opts::GetConsensusBlockCount => {
            serde_json::to_value(module.module_api.fetch_consensus_block_count().await?)
                .expect("JSON serialization failed")
        }
        Opts::RecheckDepositAddress {
            addr,
            operation_id,
            tweak_idx,
        } => {
            if u32::from(addr.is_some())
                + u32::from(operation_id.is_some())
                + u32::from(tweak_idx.is_some())
                != 1
            {
                bail!("One and only one of the selector arguments must be set")
            }
            if let Some(tweak_idx) = tweak_idx {
                module.recheck_pegin_address(tweak_idx).await?;
            } else if let Some(operation_id) = operation_id {
                module.recheck_pegin_address_by_op_id(operation_id).await?;
            } else if let Some(addr) = addr {
                module.recheck_pegin_address_by_address(addr).await?;
            } else {
                unreachable!()
            }
            serde_json::Value::Bool(true)
        }
        Opts::NewDepositAddress => {
            let (operation_id, address, tweak_idx) =
                module.allocate_deposit_address_expert_only(()).await?;
            serde_json::json! {
                {
                    "address": address,
                    "operation_id": operation_id,
                    "tweak_idx": tweak_idx.0
                }
            }
        }
    };

    Ok(res)
}
