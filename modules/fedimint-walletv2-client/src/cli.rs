use std::{ffi, iter};

use anyhow::Context;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use clap::{Parser, Subcommand};
use fedimint_core::util::SafeUrl;
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
    /// Subcommands to manage addresses.
    #[command(subcommand)]
    Address(AddressOpts),
    /// Fetch the current fee required to issue ecash for an unspent deposit.
    ReceiveFee,
    /// Issue ecash for the claimable unspent deposit of largest value.
    Receive {
        index: u64,
        #[arg(long)]
        fee: Option<bitcoin::Amount>,
        #[arg(long)]
        esplora: Option<SafeUrl>,
    },
}

#[derive(Clone, Subcommand, Serialize)]
enum InfoOpts {
    /// Fetch the total value of bitcoin controlled by the federation.
    TotalValue,
    /// Fetch the consensus block count of the federation.
    BlockCount,
    /// Fetch the current consensus feerate.
    Feerate,
    /// Fetch information on the chain of bitcoin transactions that are
    /// currently still pending.
    Pending,
    /// Retrieve info for a bitcoin transaction by index.
    Transaction { index: u64 },
    /// Display log of bitcoin transactions.
    Log { n_transactions: usize },
}

#[derive(Clone, Subcommand, Serialize)]
enum AddressOpts {
    /// Increment the address counter and return the new highest index.
    Increment,
    /// Return the number of all previously derived addresses.
    Count,
    /// Derive the address for a given index
    Derive { index: u64 },
    /// Check an address for unspent deposits and return the deposits in
    /// descending order by value.
    Check {
        index: u64,
        #[arg(long)]
        esplora: Option<SafeUrl>,
    },
}

pub(crate) async fn handle_cli_command(
    wallet: &WalletClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("walletv2")).chain(args.iter()));

    let value = match opts {
        Opts::Info(subcommand) => match subcommand {
            InfoOpts::TotalValue => json(wallet.info().total_value().await?),
            InfoOpts::BlockCount => json(wallet.info().block_count().await?),
            InfoOpts::Feerate => json(wallet.info().feerate().await?),
            InfoOpts::Pending => json(wallet.info().pending().await?),
            InfoOpts::Transaction { index } => json(
                wallet
                    .info()
                    .transaction(index)
                    .await?
                    .context("Index is out of bounds")?,
            ),
            InfoOpts::Log { n_transactions } => json(wallet.info().log(n_transactions).await?),
        },
        Opts::SendFee => json(wallet.send_fee().await?),
        Opts::Send {
            address,
            amount,
            fee,
        } => json(
            wallet
                .await_final_operation_state(wallet.send(address, amount, fee).await?)
                .await,
        ),
        Opts::Address(subcommand) => match subcommand {
            AddressOpts::Increment => json(wallet.increment_address_index().await),
            AddressOpts::Count => json(wallet.address_count().await),
            AddressOpts::Derive { index } => json(wallet.derive_address(index)),
            AddressOpts::Check { index, esplora } => {
                json(wallet.check_address_for_deposits(index, esplora).await?)
            }
        },
        Opts::ReceiveFee => json(wallet.receive_fee().await?),
        Opts::Receive {
            index,
            fee,
            esplora,
        } => {
            let deposit = wallet
                .check_address_for_deposits(index, esplora)
                .await?
                .into_iter()
                .find(|deposit| deposit.confirmations_required == Some(0))
                .context("No unspent deposits are ready to be claimed")?;

            let operation_id = wallet.receive(deposit, fee).await?;

            json(wallet.await_final_operation_state(operation_id).await)
        }
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
