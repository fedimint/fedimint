use anyhow::Result;
use bitcoin::Transaction;
use clap::{Parser, Subcommand};
use clientd::{call, PegInPayload, WaitBlockHeightPayload};
use fedimint_api::module::__reexports::serde_json;
use fedimint_core::modules::wallet::txoproof::TxOutProof;
use mint_client::utils::from_hex;
use serde::Serialize;

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
    /// rpc-method: pegin_address()
    NewPegInAddress,
    /// rpc-method: wait_block_height()
    #[clap(arg_required_else_help = true)]
    WaitBlockHeight { height: u64 },
    /// rpc-method peg_in()
    PegIn {
        /// The TxOutProof which was created from sending BTC to the pegin-address
        #[clap(parse(try_from_str = from_hex))]
        txout_proof: TxOutProof,
        /// The Bitcoin Transaction
        #[clap(parse(try_from_str = from_hex))]
        transaction: Transaction,
    },
}
#[tokio::main]
async fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Info => {
            print_json(call("", "/get_info").await, args.raw_json);
        }
        Commands::Pending => {
            print_json(call("", "/get_pending").await, args.raw_json);
        }
        Commands::NewPegInAddress => {
            print_json(call("", "/get_new_peg_in_address").await, args.raw_json);
        }
        Commands::WaitBlockHeight { height } => {
            let params = WaitBlockHeightPayload { height };
            print_json(call(&params, "/wait_block_height").await, args.raw_json);
        }
        Commands::PegIn {
            txout_proof,
            transaction,
        } => {
            let params = PegInPayload {
                txout_proof,
                transaction,
            };
            print_json(call(&params, "/peg_in").await, args.raw_json);
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
