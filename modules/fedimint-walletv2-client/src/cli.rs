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
    /// Fetch the current fee required to send an onchain payment.
    SendFee,
    /// Send an onchain payment.
    Send {
        address: Address<NetworkUnchecked>,
        value: bitcoin::Amount,
        #[arg(long)]
        fee: Option<bitcoin::Amount>,
    },
    /// Return the next unused receive address.
    Receive,
    /// Wait until a peg-in to `address` is detected and its claim has reached
    /// its final receive state.
    AwaitPegIn { address: Address<NetworkUnchecked> },
    /// Query every guardian for its local FROST finalization stat for `txid`
    /// and report the median/mean finalization time across the guardians that
    /// responded. Requires admin auth (`--our-id` + `--password`).
    FrostFinalizationStats { txid: bitcoin::Txid },
}

#[derive(Clone, Subcommand, Serialize)]
enum InfoOpts {
    /// Fetch the total value of bitcoin controlled by the federation.
    TotalValue,
    /// Fetch the consensus block count of the federation.
    BlockCount,
    /// Fetch the current consensus feerate.
    Feerate,
    /// Display the chain of pending bitcoin transactions.
    PendingTxChain,
    /// Display the chain of bitcoin transactions.
    TxChain,
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
            InfoOpts::PendingTxChain => json(wallet.pending_tx_chain().await?),
            InfoOpts::TxChain => json(wallet.tx_chain().await?),
        },
        Opts::SendFee => json(wallet.send_fee().await?),
        Opts::Send {
            address,
            value,
            fee,
        } => json(
            wallet
                .await_final_send_operation_state(wallet.send(address, value, fee).await?)
                .await,
        ),
        Opts::Receive => json(wallet.receive().await),
        Opts::AwaitPegIn { address } => json(wallet.await_peg_in(address).await?),
        Opts::FrostFinalizationStats { txid } => json(wallet.frost_finalization_stats(txid).await?),
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
