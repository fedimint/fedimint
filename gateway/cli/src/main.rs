use std::{net::SocketAddr, path::PathBuf};

use bitcoin::{Address, Amount, Transaction};
use clap::{Parser, Subcommand};
use fedimint_server::modules::wallet::txoproof::TxOutProof;
use ln_gateway::{
    config::GatewayConfig,
    rpc::{
        rpc_client::RpcClient, BalancePayload, DepositAddressPayload, DepositPayload,
        RegisterFedPayload, WithdrawPayload,
    },
};
use mint_client::{utils::from_hex, FederationId};
use url::Url;

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The address of the gateway webserver
    #[clap(short, long, default_value = "127.0.0.1:8080")]
    address: SocketAddr,
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
        /// The address of the gateway webserver
        address: SocketAddr,
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
    let url = Url::parse(&format!("http://{}", cli.address)).expect("Invalid address");
    let client = RpcClient::new(url);

    match cli.command {
        Commands::GenerateConfig {
            address,
            mut out_dir,
        } => {
            // Recursively create config directory if it doesn't exist
            std::fs::create_dir_all(&out_dir).expect("Failed to create config directory");
            // Create config file
            out_dir.push("gateway.config");

            let cfg_file =
                std::fs::File::create(out_dir).expect("Failed to create gateway config file");
            serde_json::to_writer_pretty(
                cfg_file,
                &GatewayConfig {
                    address,
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
            let response = client
                .get_info(source_password(cli.rpcpassword))
                .await
                .expect("Failed to get info");

            print_response(response).await;
        }
        Commands::Balance { federation_id } => {
            let response = client
                .get_balance(
                    source_password(cli.rpcpassword),
                    BalancePayload { federation_id },
                )
                .await
                .expect("Failed to get balance");

            print_response(response).await;
        }
        Commands::Address { federation_id } => {
            let response = client
                .get_deposit_address(
                    source_password(cli.rpcpassword),
                    DepositAddressPayload { federation_id },
                )
                .await
                .expect("Failed to get deposit address");

            print_response(response).await;
        }
        Commands::Deposit {
            federation_id,
            txout_proof,
            transaction,
        } => {
            let response = client
                .deposit(
                    source_password(cli.rpcpassword),
                    DepositPayload {
                        federation_id,
                        txout_proof,
                        transaction,
                    },
                )
                .await
                .expect("Failed to deposit");

            print_response(response).await;
        }
        Commands::Withdraw {
            federation_id,
            amount,
            address,
        } => {
            let response = client
                .withdraw(
                    source_password(cli.rpcpassword),
                    WithdrawPayload {
                        federation_id,
                        amount,
                        address,
                    },
                )
                .await
                .expect("Failed to withdraw");

            print_response(response).await;
        }
        Commands::RegisterFed { connect } => {
            let response = client
                .register_federation(
                    source_password(cli.rpcpassword),
                    RegisterFedPayload { connect },
                )
                .await
                .expect("Failed to register federation");

            print_response(response).await;
        }
    }
}

pub async fn print_response(response: reqwest::Response) {
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
