use bitcoin::Transaction;
use clap::{Parser, Subcommand};
use minimint::modules::mint::tiered::coins::Coins;
use minimint::modules::wallet::txoproof::TxOutProof;
use minimint_api::encoding::Decodable;
use minimint_api::Amount;
use mint_client::jsonrpc::client::JsonRpc;
use mint_client::jsonrpc::error::Error;
use mint_client::jsonrpc::json::*;
use mint_client::mint::SpendableCoin;
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
    /// rpc-method: get_info()
    Info,
    /// rpc-method: get_pending()
    Pending,
    /// rpc-method: get_events(timestamp: u64)
    #[clap(arg_required_else_help = true)]
    Events {
        /// Unix timestamp
        timestamp: u64,
    },
    /// rpc-method: get_new_pegin_address()
    NewPeginAddress,
    /// rpc-method: peg_in(pegin_req: {tx_out_proof, transaction})
    #[clap(arg_required_else_help = true)]
    PegIn {
        /// todo comment
        #[clap(parse(try_from_str = from_hex))]
        txout_proof: TxOutProof,
        /// todo comment
        #[clap(parse(try_from_str = from_hex))]
        transaction: Transaction,
    },
    /// rpc-method: peg_out(pegout_req: {address, amount})
    #[clap(arg_required_else_help = true)]
    PegOut {
        /// A bitcoin address
        address: bitcoin::Address,
        /// A bitcoin amount
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
    /// rpc-method: reissue(coins: Coins<SpendableCoin>)
    #[clap(arg_required_else_help = true)]
    Reissue {
        /// The base64 encoded coins
        #[clap(parse(from_str = parse_coins))]
        coins: Coins<SpendableCoin>,
        #[clap(takes_value = false, long = "quiet", short = 'q')]
        /// call rpc-method as a 'notification'
        quiet: bool,
    },
}
#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let jsonrpc = JsonRpc::default(); //how will the cli normaly ask for the host ?

    match args.command {
        Commands::Info => {
            info(&jsonrpc, args.raw_json).await;
        }
        Commands::Pending => {
            pending(&jsonrpc, args.raw_json).await;
        }
        Commands::Events { timestamp } => {
            events(&jsonrpc, timestamp, args.raw_json).await;
        }
        Commands::NewPeginAddress => {
            new_pegin_address(&jsonrpc, args.raw_json).await;
        }
        Commands::PegIn {
            txout_proof,
            transaction,
        } => {
            let pegin_request = PegInReq {
                txout_proof,
                transaction,
            };
            pegin(&jsonrpc, pegin_request, args.raw_json).await;
        }
        Commands::PegOut { address, amount } => {
            let pegout_request = PegOutReq { address, amount };
            pegout(&jsonrpc, pegout_request, args.raw_json).await;
        }
        Commands::Spend { amount, raw_coins } => {
            spend(&jsonrpc, amount, args.raw_json, raw_coins).await;
        }
        Commands::LnPay { bolt11 } => {
            let inv_req = InvoiceReq { bolt11 };
            lnpay(&jsonrpc, inv_req, args.raw_json).await;
        }
        Commands::Reissue { coins, quiet } => {
            reissue(&jsonrpc, coins, quiet, args.raw_json).await;
        }
    }
}

async fn info(jsonrpc: &JsonRpc, raw: bool) {
    let response = jsonrpc.get_info().await;
    handle_rpc_response(response, raw);
}
async fn pending(jsonrpc: &JsonRpc, raw: bool) {
    let response = jsonrpc.get_pending().await;
    handle_rpc_response(response, raw);
}
async fn events(jsonrpc: &JsonRpc, ts: u64, raw: bool) {
    let response = jsonrpc.get_events(ts).await;
    handle_rpc_response(response, raw);
}
async fn new_pegin_address(jsonrpc: &JsonRpc, raw: bool) {
    let response = jsonrpc.get_new_pegin_address().await;
    handle_rpc_response(response, raw);
}
async fn pegin(jsonrpc: &JsonRpc, pegin_request: PegInReq, raw: bool) {
    let response = jsonrpc.peg_in(pegin_request).await;
    handle_rpc_response(response, raw);
}
async fn pegout(jsonrpc: &JsonRpc, pegout_request: PegOutReq, raw: bool) {
    let response = jsonrpc.peg_out(pegout_request).await;
    handle_rpc_response(response, raw);
}
async fn spend(jsonrpc: &JsonRpc, amount: Amount, raw: bool, raw_coins: bool) {
    let response = jsonrpc.spend(amount).await;
    if !raw_coins {
        let response = response.map(|r| serialize_coins(&r.coins));
        handle_rpc_response(response, raw);
    } else {
        handle_rpc_response(response, raw);
    }
}
async fn lnpay(jsonrpc: &JsonRpc, inv_req: InvoiceReq, raw: bool) {
    let response = jsonrpc.lnpay(inv_req).await;
    handle_rpc_response(response, raw);
}
async fn reissue(jsonrpc: &JsonRpc, coins: Coins<SpendableCoin>, quiet: bool, raw: bool) {
    if quiet {
        #[allow(unused_must_use)]
        {
            jsonrpc.reissue(coins).await;
        }
    } else {
        let response = jsonrpc.reissue_validate(coins).await;
        handle_rpc_response(response, raw);
    }
}
fn handle_rpc_response<T: Serialize>(response: Result<T, Error>, raw: bool) {
    match response {
        Ok(result) => print_json(result, raw),
        Err(Error::Rpc(error)) => print_json(error, raw),
        _ => eprintln!("this should not happen, restart clientd"),
    }
}
fn print_json<T: Serialize>(p: T, raw: bool) {
    if raw {
        println!("{}", serde_json::to_string(&p).unwrap());
    } else {
        println!("{}", serde_json::to_string_pretty(&p).unwrap());
    }
}

fn from_hex<D: Decodable>(
    s: &str,
) -> Result<D, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let bytes = hex::decode(s)?;
    Ok(D::consensus_decode(std::io::Cursor::new(bytes))?)
}
fn parse_coins(s: &str) -> Coins<SpendableCoin> {
    let bytes = base64::decode(s).unwrap();
    bincode::deserialize(&bytes).unwrap()
}
fn serialize_coins(c: &Coins<SpendableCoin>) -> String {
    let bytes = bincode::serialize(&c).unwrap();
    base64::encode(&bytes)
}
