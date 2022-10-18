use bitcoin::{Address, Amount, Transaction};
use clap::{Parser, Subcommand};
use fedimint_server::modules::wallet::txoproof::TxOutProof;
use ln_gateway::{BalancePayload, DepositAddressPayload, DepositPayload, WithdrawPayload};
use mint_client::utils::from_hex;
use serde::Serialize;

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The address of the gateway webserver
    #[clap(short, long, default_value = "http://localhost:8080")]
    url: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Display CLI version hash
    VersionHash,
    /// Display high-level information about the Gateway
    Info,
    /// Check gateway balance
    /// TODO: add federation id to scope the federation for which we want a pegin address
    Balance,
    /// Generate a new peg-in address, funds sent to it can later be claimed
    Address,
    /// Deposit funds into a gateway federation
    /// TODO: add federation id to scope the federation for which we want a pegin address
    Deposit {
        /// The TxOutProof which was created from sending BTC to the pegin-address
        #[clap(value_parser = from_hex::<TxOutProof>)]
        txout_proof: TxOutProof,
        #[clap(value_parser = from_hex::<Transaction>)]
        transaction: Transaction,
    },
    /// Claim funds from a gateway federation
    /// TODO: add federation id to scope the federation for which we want a pegin address
    Withdraw {
        /// The amount to withdraw
        amount: Amount,
        /// The address to send the funds to
        address: Address,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::VersionHash => {
            println!("version: {}", env!("GIT_HASH"));
        }
        Commands::Info => {
            call(cli.url, String::from("/info"), ()).await;
        }
        Commands::Balance => {
            call(cli.url, String::from("/balance"), BalancePayload {}).await;
        }
        Commands::Address => {
            call(cli.url, String::from("/address"), DepositAddressPayload {}).await;
        }
        Commands::Deposit {
            txout_proof,
            transaction,
        } => {
            call(
                cli.url,
                String::from("/deposit"),
                DepositPayload {
                    txout_proof,
                    transaction,
                },
            )
            .await;
        }
        Commands::Withdraw { amount, address } => {
            call(
                cli.url,
                String::from("/withdraw"),
                WithdrawPayload { amount, address },
            )
            .await;
        }
    }
}

pub async fn call<P>(url: String, endpoint: String, payload: P)
where
    P: Serialize,
{
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}{}", url, endpoint))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await
        .expect("rpc call failed");

    match response.status() {
        reqwest::StatusCode::OK => {
            let val: serde_json::Value = serde_json::from_str(&response.text().await.unwrap())
                .expect("failed to parse response");
            let formatted = serde_json::to_string_pretty(&val).expect("failed to format response");
            println!("{}", formatted)
        }
        _ => {
            println!("\nError: {}", &response.text().await.unwrap());
        }
    }
}
