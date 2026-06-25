use std::{ffi, iter};

use bitcoin::Address;
use bitcoin::address::NetworkUnchecked;
use clap::{Parser, Subcommand};
use fedimint_eventlog::EventLogId;
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
    /// Fetch the current fee required to claim an onchain deposit (peg-in).
    ReceiveFee,
    /// Send an onchain payment.
    Send {
        address: Address<NetworkUnchecked>,
        value: bitcoin::Amount,
        #[arg(long)]
        fee: Option<bitcoin::Amount>,
    },
    /// Return the next unused receive address.
    ///
    /// To wait for a payment to this address, read the current event log
    /// position with `dev next-event-log-id` *before* running this, then pass
    /// that position to `await-receive`.
    Receive,
    /// Block until the next payment is received, starting from the given event
    /// log position. Returns the receive's final state and the event log
    /// position to pass to the following `await-receive`.
    AwaitReceive {
        /// Event log position to start scanning from, as returned by
        /// `dev next-event-log-id` or a prior `await-receive`.
        position: EventLogId,
    },
    /// Query this client's own guardian (selected via `--our-id`) for its local
    /// FROST finalization stat for `txid`. Returns `null` if that guardian is
    /// offline or hasn't recorded a stat for `txid`. Requires admin auth
    /// (`--our-id` + `--password`).
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
        Opts::ReceiveFee => json(wallet.receive_fee().await?),
        Opts::Send {
            address,
            value,
            fee,
        } => json(
            wallet
                .await_final_send_operation_state(
                    wallet
                        .send(address, value, fee, serde_json::Value::Null)
                        .await?,
                )
                .await?,
        ),
        Opts::Receive => json(wallet.receive().await),
        Opts::AwaitReceive { position } => json(wallet.await_receive(position).await?),
        Opts::FrostFinalizationStats { txid } => json(wallet.frost_finalization_stats(txid).await?),
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
