use std::{ffi, iter};

use bitcoin::Address;
use bitcoin::address::NetworkUnchecked;
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;

use crate::WalletClientModule;

#[derive(Parser, Serialize)]
enum Opts {
    /// Subcommands for operator to retrieve information about the wallet state.
    #[command(subcommand)]
    Info(InfoOpts),
    /// Fetch the current fee required to send an on-chain payment.
    SendFee,
    /// Send an on-chain payment.
    Send {
        address: Address<NetworkUnchecked>,
        amount: bitcoin::Amount,
        #[arg(long)]
        fee: Option<bitcoin::Amount>,
    },
    /// Return the next unused deposit address.
    Receive,
}

#[derive(Clone, Subcommand, Serialize)]
enum InfoOpts {
    /// Fetch the total value of bitcoin controlled by the federation.
    TotalValue,
    /// Fetch the consensus block count of the federation.
    BlockCount,
    /// Fetch the current consensus feerate.
    Feerate,
    /// Display the chain of bitcoin transactions that are still pending.
    PendingTransactionChain,
    /// Display the chain of bitcoin transactions.
    TransactionChain { n: usize },
}

pub(crate) async fn handle_cli_command(
    wallet: &WalletClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("walletv2")).chain(args.iter()));

    let value = match opts {
        Opts::Info(subcommand) => match subcommand {
            InfoOpts::TotalValue => json(wallet.total_value().await?),
            InfoOpts::BlockCount => json(wallet.block_count().await?),
            InfoOpts::Feerate => json(wallet.feerate().await?),
            InfoOpts::PendingTransactionChain => json(wallet.pending_transaction_chain().await?),
            InfoOpts::TransactionChain { n } => json(wallet.transaction_chain(n).await?),
        },
        Opts::SendFee => json(wallet.send_fee().await?),
        Opts::Send {
            address,
            amount,
            fee,
        } => json(
            wallet
                .await_final_send_operation_state(wallet.send(address, amount, fee).await?)
                .await,
        ),
        Opts::Receive => json(wallet.receive().await),
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
