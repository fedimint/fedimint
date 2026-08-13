use std::{ffi, iter};

use bitcoin::Address;
use bitcoin::address::NetworkUnchecked;
use clap::{Parser, Subcommand};
use fedimint_core::BitcoinAmountOrAll;
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
        /// Value to send, or "all" to sweep the entire balance.
        value: BitcoinAmountOrAll,
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
        } => {
            // Resolve the on-chain fee up front so the same value sizes the
            // sweep and funds the send: the required feerate rises with each
            // pending federation transaction, and a value computed against a
            // stale fee would be rejected.
            let fee = match fee {
                Some(fee) => fee,
                None => wallet.send_fee().await?,
            };

            let value = match value {
                // The on-chain fee is only part of the cost of sending
                // everything: funding the wallet output also incurs the
                // federation's per-note fees.
                BitcoinAmountOrAll::All => {
                    let balance = wallet.client_ctx.get_balance_for_btc().await?;
                    wallet.max_sendable_amount(balance, fee).await?
                }
                BitcoinAmountOrAll::Amount(value) => value,
            };

            json(
                wallet
                    .await_final_send_operation_state(
                        wallet
                            .send(address, value, Some(fee), serde_json::Value::Null)
                            .await?,
                    )
                    .await?,
            )
        }
        Opts::Receive => json(wallet.receive().await),
        Opts::AwaitReceive { position } => json(wallet.await_receive(position).await?),
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
