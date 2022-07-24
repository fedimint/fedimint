use anyhow::Result;
use clap::{Parser, Subcommand};
use clientd::call;
use minimint_api::module::__reexports::serde_json;
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
