use std::{ffi, iter};

use anyhow::Context;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use clap::Parser;
use clap::Subcommand;
use fedimint_core::util::SafeUrl;
use serde::Serialize;
use serde_json::Value;

use crate::WalletClientModule;

#[derive(Parser, Serialize)]
enum Opts {
    /// Fetch the current fee required to send an on-chain payment.
    SendFee,
    /// Send an on-chain payment.
    Send {
        address: Address<NetworkUnchecked>,
        amount: bitcoin::Amount,
        #[arg(long)]
        fee_limit: Option<bitcoin::Amount>,
    },
    /// Subcommands to manage addresses
    #[command(subcommand)]
    Address(AddressOpts),
    /// Fetch the current fee required to issue ecash for an unspent deposit.
    ReceiveFee,
    /// Issue ecash for the claimable unspent deposit of largest value.
    Receive {
        esplora: SafeUrl,
        index: u64,
        #[arg(long)]
        fee_limit: Option<bitcoin::Amount>,
    },
}

#[derive(Clone, Subcommand, Serialize)]
enum AddressOpts {
    /// Increment the address counter and return the new highest index.
    Increment,
    /// Return the number of all previously derived addresses.
    Count,
    Derive {
        index: u64,
    },
    /// Check an address for unspent deposits and return the deposits in
    /// descending order by value.
    Check {
        esplora: SafeUrl,
        index: u64,
    },
}

pub(crate) async fn handle_cli_command(
    wallet: &WalletClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("walletv2")).chain(args.iter()));

    let value = match opts {
        Opts::SendFee => json(wallet.send_fee().await?),
        Opts::Send {
            address,
            amount,
            fee_limit,
        } => {
            let operation_id = wallet.send(&address, amount, fee_limit).await?;

            json(wallet.await_final_operation_state(operation_id).await)
        }
        Opts::Address(subcommand) => match subcommand {
            AddressOpts::Increment => json(wallet.increment_address_index().await),
            AddressOpts::Count => json(wallet.address_count().await),
            AddressOpts::Derive { index } => json(wallet.derive_address(index)),
            AddressOpts::Check { esplora, index } => {
                json(wallet.check_address_for_deposits(esplora, index).await?)
            }
        },
        Opts::ReceiveFee => json(wallet.receive_fee().await?),
        Opts::Receive {
            esplora,
            index,
            fee_limit,
        } => {
            let deposit = wallet
                .check_address_for_deposits(esplora, index)
                .await?
                .into_iter()
                .find(|deposit| deposit.confirmations_required == Some(0))
                .context("No unspent deposits are ready to be claimed")?;

            let operation_id = wallet.receive(&deposit, fee_limit).await?;

            json(wallet.await_final_operation_state(operation_id).await)
        }
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
