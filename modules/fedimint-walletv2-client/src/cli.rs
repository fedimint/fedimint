use std::{ffi, iter};

use anyhow::{ensure, Context};
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use clap::Parser;
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
    /// Generate a new address controlled by the federation.
    Generate,
    /// List all previously generated addresses.
    List,
    /// Check an address for unspent deposits and return the deposits in
    /// descending order by value.
    Check { esplora: SafeUrl, index: u64 },

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

pub(crate) async fn handle_cli_command(
    wallet: &WalletClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("walletv2")).chain(args.iter()));

    let value = match opts {
        Opts::SendFee => json(wallet.send_fee().await.map(|fee| fee.value)?),
        Opts::Send {
            address,
            amount,
            fee_limit: fee,
        } => {
            let send_fee = wallet.send_fee().await?;

            if let Some(fee) = fee {
                ensure!(
                    send_fee.value <= fee,
                    "The currently required fee exceeds the specified limit of {fee}"
                );
            }

            let operation_id = wallet.send(&address, amount, send_fee).await?;

            json(wallet.await_final_operation_state(operation_id).await)
        }
        Opts::Generate => json(wallet.generate_new_address().await),
        Opts::List => json(wallet.list_addresses().await),
        Opts::Check { esplora, index } => {
            json(wallet.check_address_for_deposits(esplora, index).await?)
        }
        Opts::ReceiveFee => json(wallet.receive_fee().await.map(|fee| fee.value)?),
        Opts::Receive {
            esplora,
            index,
            fee_limit: fee,
        } => {
            let deposit = wallet
                .check_address_for_deposits(esplora, index)
                .await?
                .into_iter()
                .find(|deposit| deposit.confirmations_required == Some(0))
                .context("No unspent deposits are ready to be claimed")?;

            let receive_fee = wallet.receive_fee().await?;

            if let Some(fee) = fee {
                ensure!(
                    receive_fee.value <= fee,
                    "The currently required fee exceeds the specified limit of {fee}"
                );
            }

            let operation_id = wallet.receive(&deposit, receive_fee).await?;

            json(wallet.await_final_operation_state(operation_id).await)
        }
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
