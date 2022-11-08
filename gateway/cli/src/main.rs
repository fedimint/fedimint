use std::path::PathBuf;

use bitcoin::{Address, Amount, Transaction};
use clap::{Parser, Subcommand};
use fedimint_server::modules::wallet::txoproof::TxOutProof;
use ln_gateway::{
    config::GatewayConfig,
    rpc::{
        BalancePayload, DepositAddressPayload, DepositPayload, RegisterFedPayload, WithdrawPayload,
    },
};
use mint_client::{utils::from_hex, FederationId};
use serde::Serialize;

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The address of the gateway webserver
    #[clap(short, long, default_value = "http://localhost:8080")]
    url: String,
    #[command(subcommand)]
    command: Commands,
    /// WARNING: Passing in a password from the command line may be less secure!
    #[clap(long)]
    rpcpassword: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Ganerate gateway configuration
    /// NOTE: This command can only be used on a local gateway
    GenerateConfig {
        /// The gateway configuration directory
        out_dir: PathBuf,
    },
    /// Display CLI version hash
    VersionHash,
    /// Display high-level information about the Gateway
    Info,
    /// Check gateway balance
    /// TODO: add federation id to scope the federation for which we want a pegin address
    Balance { federation_id: FederationId },
    /// Generate a new peg-in address, funds sent to it can later be claimed
    Address { federation_id: FederationId },
    /// Deposit funds into a gateway federation
    /// TODO: add federation id to scope the federation for which we want a pegin address
    Deposit {
        federation_id: FederationId,
        /// The TxOutProof which was created from sending BTC to the pegin-address
        #[clap(value_parser = from_hex::<TxOutProof>)]
        txout_proof: TxOutProof,
        #[clap(value_parser = from_hex::<Transaction>)]
        transaction: Transaction,
    },
    /// Claim funds from a gateway federation
    /// TODO: add federation id to scope the federation for which we want a pegin address
    Withdraw {
        federation_id: FederationId,
        /// The amount to withdraw
        amount: Amount,
        /// The address to send the funds to
        address: Address,
    },
    /// Register federation with the gateway
    RegisterFed {
        /// ConnectInfo code to connect to the federation
        connect: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenerateConfig { mut out_dir } => {
            // Recursively create config directory if it doesn't exist
            std::fs::create_dir_all(&out_dir).expect("Failed to create config directory");
            // Create config file
            out_dir.push("gateway.config");

            let cfg_file =
                std::fs::File::create(out_dir).expect("Failed to create gateway config file");
            serde_json::to_writer_pretty(
                cfg_file,
                &GatewayConfig {
                    // TODO: Generate a strong random password
                    password: source_password(cli.rpcpassword),
                    // TODO: Remove this field with hardcoded value once we have fixed Issue 664:
                    default_federation: FederationId("Hals_trusty_mint".into()),
                },
            )
            .expect("Failed to write gateway configs to file");
        }
        Commands::VersionHash => {
            println!("version: {}", env!("GIT_HASH"));
        }
        Commands::Info => {
            call(
                source_password(cli.rpcpassword),
                cli.url,
                String::from("/info"),
                (),
            )
            .await;
        }
        Commands::Balance { federation_id } => {
            call(
                source_password(cli.rpcpassword),
                cli.url,
                String::from("/balance"),
                BalancePayload { federation_id },
            )
            .await;
        }
        Commands::Address { federation_id } => {
            call(
                source_password(cli.rpcpassword),
                cli.url,
                String::from("/address"),
                DepositAddressPayload { federation_id },
            )
            .await;
        }
        Commands::Deposit {
            federation_id,
            txout_proof,
            transaction,
        } => {
            call(
                source_password(cli.rpcpassword),
                cli.url,
                String::from("/deposit"),
                DepositPayload {
                    federation_id,
                    txout_proof,
                    transaction,
                },
            )
            .await;
        }
        Commands::Withdraw {
            federation_id,
            amount,
            address,
        } => {
            call(
                source_password(cli.rpcpassword),
                cli.url,
                String::from("/withdraw"),
                WithdrawPayload {
                    federation_id,
                    amount,
                    address,
                },
            )
            .await;
        }
        Commands::RegisterFed { connect } => {
            call(
                source_password(cli.rpcpassword),
                cli.url,
                String::from("/register"),
                RegisterFedPayload { connect },
            )
            .await;
        }
    }
}

pub async fn call<P>(password: String, url: String, endpoint: String, payload: P)
where
    P: Serialize,
{
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}{}", url, endpoint))
        .bearer_auth(password)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await
        .expect("rpc call failed");

    match response.status() {
        reqwest::StatusCode::OK => {
            let text = response.text().await.expect("Failed to read response body");
            if !text.is_empty() {
                let val: serde_json::Value =
                    serde_json::from_str(&text).expect("failed to parse response as json");
                let formatted =
                    serde_json::to_string_pretty(&val).expect("failed to format response");
                println!("\n{}", formatted)
            }
        }
        _ => {
            println!("\nError: {}", &response.text().await.unwrap());
        }
    }
}

pub fn source_password(rpcpassword: Option<String>) -> String {
    match rpcpassword {
        None => rpassword::prompt_password("Enter gateway password:").unwrap(),
        Some(password) => {
            eprintln!("WARNING: Passing in a password from the command line may be less secure!");
            password
        }
    }
}
