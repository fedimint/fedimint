use anyhow::Result;
use bitcoin::Transaction;
use clap::{Parser, Subcommand};
use clientd::call;
use clientd::payload::{LnPayPayload, PeginPayload, PegoutPayload};
use clientd::responses::{RpcResult, SpendResponse};
use minimint_api::Amount;
use minimint_core::modules::mint::tiered::coins::Coins;
use minimint_core::modules::wallet::txoproof::TxOutProof;
use mint_client::mint::SpendableCoin;
use mint_client::utils::{from_hex, parse_bitcoin_amount, parse_coins};
use serde::Serialize;
use serde_json::json;

#[derive(Parser)]
#[clap(author, version, about = "a json-rpc cli application")]
struct Cli {
    /// print unformatted json
    #[clap(takes_value = false, long = "raw", short = 'r')]
    raw_json: bool,
    /// call JSON-2.0 RPC method
    #[clap(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// rpc-method: info()
    Info,
    /// rpc-method: pending()
    Pending,
    /// rpc-method: events(timestamp: u64)
    #[clap(arg_required_else_help = true)]
    Events {
        /// Unix timestamp
        timestamp: u64,
    },
    /// rpc-method: pegin_address()
    NewPeginAddress,
    /// rpc-method: pegin(pegin: {tx_out_proof, transaction})
    #[clap(arg_required_else_help = true)]
    PegIn {
        /// The TxOutProof which was created from sending BTC to the pegin-address
        #[clap(parse(try_from_str = from_hex))]
        txout_proof: TxOutProof,
        /// The Bitcoin Transaction
        #[clap(parse(try_from_str = from_hex))]
        transaction: Transaction,
    },
    /// rpc-method: peg_out(pegout_req: {address, amount})
    #[clap(arg_required_else_help = true)]
    PegOut {
        /// A bitcoin address
        address: bitcoin::Address,
        /// The bitcoin amount in satoshis (not msat!)
        #[clap(parse(try_from_str = parse_bitcoin_amount))]
        amount: bitcoin::Amount,
    },
    /// rpc-method: spend(amount: Amount)
    #[clap(arg_required_else_help = true)]
    Spend {
        /// A minimint (ecash) amount
        amount: Amount,
        /// don't encode coins
        #[clap(takes_value = false, long = "raw", short = 'r')]
        raw_coins: bool,
    },
    /// rpc-method: lnpay(invoice_req: {bolt11: Invoice})
    LnPay {
        /// The amount of coins to be spend in msat if not set to sat
        #[clap(parse(try_from_str = str::parse::<lightning_invoice::Invoice>))]
        bolt11: lightning_invoice::Invoice,
    },
    /// rpc-method: reissue_validate(coins: Coins<SpendableCoin>)
    #[clap(arg_required_else_help = true)]
    Reissue {
        /// The base64 encoded coins
        #[clap(parse(from_str = parse_coins))]
        coins: Coins<SpendableCoin>,
        #[clap(takes_value = false, long = "quiet", short = 'q')]
        /// call reissue without validation
        quiet: bool,
    },
}
#[tokio::main]
async fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Info => {
            print_json(call("", "/getInfo").await, args.raw_json);
        }
        Commands::Pending => {
            print_json(call("", "/getPending").await, args.raw_json);
        }
        Commands::Events { timestamp } => {
            print_json(call(&timestamp, "/getEvents").await, args.raw_json);
        }
        Commands::NewPeginAddress => {
            print_json(call("", "/getPeginAdress").await, args.raw_json);
        }
        Commands::PegIn {
            txout_proof,
            transaction,
        } => {
            let params = PeginPayload {
                txout_proof,
                transaction,
            };
            print_json(call(&params, "/pegin").await, args.raw_json);
        }
        Commands::PegOut { address, amount } => {
            let params = PegoutPayload { address, amount };
            print_json(call(&params, "/pegout").await, args.raw_json);
        }
        Commands::Spend { amount, raw_coins } => {
            let res = call(&amount, "/spend").await.map(|r| {
                if raw_coins {
                    r
                } else if let RpcResult::Success(v) = r {
                    let coins: SpendResponse = serde_json::from_value(v).unwrap();
                    let coins = coins.serialized();
                    RpcResult::Success(json!(coins))
                } else {
                    r
                }
            });
            print_json(res, args.raw_json);
        }
        Commands::LnPay { bolt11 } => {
            let params = LnPayPayload { bolt11 };
            print_json(call(&params, "/lnpay").await, args.raw_json);
        }
        Commands::Reissue { coins, quiet } => {
            if quiet {
                print_json(call(&coins, "/reissue").await, args.raw_json);
            } else {
                print_json(call(&coins, "/reissueValidate").await, args.raw_json);
            }
        }
    }
}

fn print_json<T: Serialize>(result: Result<T>, raw: bool) {
    match result {
        Ok(p) => {
            if raw {
                println!("{}", serde_json::to_string(&p).unwrap());
            } else {
                println!("{}", serde_json::to_string_pretty(&p).unwrap());
            }
        }
        Err(e) => eprintln!("{}", e),
    }
}
