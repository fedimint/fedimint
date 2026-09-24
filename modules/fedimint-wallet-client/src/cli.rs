use std::str::FromStr as _;
use std::{ffi, iter};

use bitcoin::address::NetworkUnchecked;
use clap::Parser;
use fedimint_api_client::api::FederationError;
use fedimint_client_module::error::{ModuleLookupError, TransactionSubmitError};
use fedimint_core::BitcoinAmountOrAll;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::Encodable;
use futures::StreamExt;
use serde::Serialize;
use tracing::{debug, info};

use super::WalletClientModule;
use crate::api::WalletFederationApi;
use crate::client_db::TweakIdx;
use crate::{
    DepositAddressError, MaxWithdrawableAmountError, PegInError, SubscribeWithdrawError,
    WithdrawFeesError, WithdrawState,
};

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
    /// Withdraw funds from the federation
    Withdraw {
        #[clap(long)]
        amount: BitcoinAmountOrAll,
        #[clap(long)]
        address: bitcoin::Address<NetworkUnchecked>,
    },
    /// Trigger wallet address check (in the background)
    RecheckDepositAddress {
        addr: Option<bitcoin::Address<NetworkUnchecked>>,
        #[arg(long)]
        operation_id: Option<OperationId>,
        #[arg(long)]
        tweak_idx: Option<TweakIdx>,
    },
}

async fn await_deposit(
    module: &WalletClientModule,
    addr: Option<String>,
    operation_id: Option<OperationId>,
    tweak_idx: Option<TweakIdx>,
    num: usize,
) -> Result<(), CliCommandError> {
    if u32::from(addr.is_some())
        + u32::from(operation_id.is_some())
        + u32::from(tweak_idx.is_some())
        != 1
    {
        return Err(CliCommandError::SelectorCount);
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
                "Interpreting addr as an operation_id for backward compatibility. \
                Use `--operation-id` from now on."
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
    Ok(())
}

async fn withdraw(
    module: &WalletClientModule,
    amount: BitcoinAmountOrAll,
    address: bitcoin::Address<NetworkUnchecked>,
) -> Result<serde_json::Value, CliCommandError> {
    let address = address.require_network(module.get_network())?;
    let (amount, fees) = match amount {
        // The on-chain fee is only part of the cost of withdrawing everything:
        // funding the peg-out output also incurs the federation's per-note
        // fees. The returned fees are quoted at the returned amount, so they
        // must be used together.
        BitcoinAmountOrAll::All => {
            let balance = module.client_ctx.get_balance_for_btc().await?;
            module.max_withdrawable_amount(&address, balance).await?
        }
        BitcoinAmountOrAll::Amount(amount) => {
            (amount, module.get_withdraw_fees(&address, amount).await?)
        }
    };
    let absolute_fees = fees.amount();

    info!("Attempting withdraw with fees: {fees:?}");

    let operation_id = module.withdraw(&address, amount, fees, ()).await?;

    let mut updates = module
        .subscribe_withdraw_updates(operation_id)
        .await?
        .into_stream();

    while let Some(update) = updates.next().await {
        debug!(?update, "Withdraw state update");

        match update {
            WithdrawState::Succeeded(txid) => {
                return Ok(serde_json::json!({
                    "txid": txid.consensus_encode_to_hex(),
                    "fees_sat": absolute_fees.to_sat(),
                }));
            }
            WithdrawState::Failed(e) => {
                return Err(CliCommandError::WithdrawFailed(e));
            }
            WithdrawState::Created => {}
        }
    }

    unreachable!("Update stream ended without outcome");
}

pub(crate) async fn handle_cli_command(
    module: &WalletClientModule,
    args: &[ffi::OsString],
) -> Result<serde_json::Value, CliCommandError> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("wallet")).chain(args.iter()));

    let res = match opts {
        Opts::AwaitDeposit {
            operation_id,
            num,
            addr,
            tweak_idx,
        } => {
            await_deposit(module, addr, operation_id, tweak_idx, num).await?;
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
                .ok_or(CliCommandError::AdminAuthNotSet)?;
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
                return Err(CliCommandError::SelectorCount);
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
            let deposit_address = module.allocate_deposit_address_expert_only(()).await?;
            serde_json::json! {
                {
                    "address": deposit_address.address,
                    "operation_id": deposit_address.operation_id,
                    "tweak_idx": deposit_address.tweak_idx.0
                }
            }
        }
        Opts::Withdraw { amount, address } => return withdraw(module, amount, address).await,
    };

    Ok(res)
}

/// A failure of a `wallet` module command.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CliCommandError {
    /// Not exactly one of the address, operation id and tweak index was
    /// given.
    #[error("One and only one of the selector arguments must be set")]
    SelectorCount,

    /// The deposits could not be awaited or rechecked.
    #[error(transparent)]
    PegIn(#[from] PegInError),

    /// The argument is not a valid operation id.
    #[error(transparent)]
    OperationId(#[from] fedimint_core::hex::FromHexError),

    /// The address is not valid, or not for the federation's network.
    #[error(transparent)]
    Address(#[from] bitcoin::address::ParseError),

    /// The client's bitcoin balance could not be read.
    #[error(transparent)]
    Balance(#[from] ModuleLookupError),

    /// The largest withdrawable amount could not be computed.
    #[error(transparent)]
    MaxWithdrawable(#[from] MaxWithdrawableAmountError),

    /// The withdrawal fees could not be quoted.
    #[error(transparent)]
    WithdrawFees(#[from] WithdrawFeesError),

    /// The withdrawal transaction could not be submitted.
    #[error(transparent)]
    Withdraw(#[from] TransactionSubmitError),

    /// The withdrawal's updates could not be followed.
    #[error(transparent)]
    SubscribeWithdraw(#[from] SubscribeWithdrawError),

    /// The withdrawal failed.
    #[error("Withdraw failed: {0}")]
    WithdrawFailed(String),

    /// The federation did not serve the request.
    #[error(transparent)]
    Federation(#[from] FederationError),

    /// The client has no admin credentials, which reading the Bitcoin RPC
    /// config needs.
    #[error("Admin auth not set")]
    AdminAuthNotSet,

    /// A deposit address could not be allocated.
    #[error(transparent)]
    DepositAddress(#[from] DepositAddressError),
}
