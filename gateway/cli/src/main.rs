use std::process::exit;

use bitcoin::{Address, Amount, Transaction};
use clap::{Parser, Subcommand};
use fedimint_client_legacy::utils::from_hex;
use fedimint_core::config::FederationId;
use fedimint_core::txoproof::TxOutProof;
use fedimint_logging::TracingSetup;
use ln_gateway::rpc::rpc_client::RpcClient;
use ln_gateway::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload,
    LightningReconnectPayload, RestorePayload, WithdrawPayload,
};
use ln_gateway::LightningMode;
use url::Url;

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The address of the gateway webserver
    #[clap(short, long, default_value = "http://127.0.0.1:8175")]
    address: Url,
    #[command(subcommand)]
    command: Commands,
    /// WARNING: Passing in a password from the command line may be less secure!
    #[clap(long)]
    rpcpassword: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Display CLI version hash
    VersionHash,
    /// Display high-level information about the Gateway
    Info,
    /// Check gateway balance
    Balance {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Generate a new peg-in address, funds sent to it can later be claimed
    Address {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Deposit funds into a gateway federation
    Deposit {
        #[clap(long)]
        federation_id: FederationId,
        /// The TxOutProof which was created from sending BTC to the
        /// pegin-address
        #[clap(long, value_parser = from_hex::<TxOutProof>)]
        txout_proof: TxOutProof,
        #[clap(long, value_parser = from_hex::<Transaction>)]
        transaction: Transaction,
    },
    /// Claim funds from a gateway federation
    Withdraw {
        #[clap(long)]
        federation_id: FederationId,
        /// The amount to withdraw
        #[clap(long)]
        amount: Amount,
        /// The address to send the funds to
        #[clap(long)]
        address: Address,
    },
    /// Register federation with the gateway
    ConnectFed {
        /// ConnectInfo code to connect to the federation
        connect: String,
    },
    /// Make a backup of snapshot of all ecash
    Backup {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Restore ecash from last available snapshot or from scratch
    Restore {
        #[clap(long)]
        federation_id: FederationId,
    },
    // Reconnect to the Lightning Node
    ReconnectLightning {
        #[clap(subcommand)]
        lightning_mode: LightningMode,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli = Cli::parse();
    let client = RpcClient::new(cli.address);

    match cli.command {
        Commands::VersionHash => {
            println!("version: {}", env!("CODE_VERSION"));
        }
        Commands::Info => {
            let response = client.get_info(source_password(cli.rpcpassword)).await?;

            print_response(response).await;
        }
        Commands::Balance { federation_id } => {
            let response = client
                .get_balance(
                    source_password(cli.rpcpassword),
                    BalancePayload { federation_id },
                )
                .await?;

            print_response(response).await;
        }
        Commands::Address { federation_id } => {
            let response = client
                .get_deposit_address(
                    source_password(cli.rpcpassword),
                    DepositAddressPayload { federation_id },
                )
                .await?;

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
                .await?;

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
                .await?;

            print_response(response).await;
        }
        Commands::ConnectFed { connect } => {
            let response = client
                .connect_federation(
                    source_password(cli.rpcpassword),
                    ConnectFedPayload { connect },
                )
                .await?;

            print_response(response).await;
        }
        Commands::Backup { federation_id } => {
            let response = client
                .backup(
                    source_password(cli.rpcpassword),
                    BackupPayload { federation_id },
                )
                .await?;

            print_response(response).await;
        }
        Commands::Restore { federation_id } => {
            let response = client
                .restore(
                    source_password(cli.rpcpassword),
                    RestorePayload { federation_id },
                )
                .await?;

            print_response(response).await;
        }
        Commands::ReconnectLightning { lightning_mode } => {
            let payload = match lightning_mode {
                LightningMode::Cln { cln_extension_addr } => LightningReconnectPayload {
                    node_type: Some(LightningMode::Cln { cln_extension_addr }),
                },
                LightningMode::Lnd {
                    lnd_rpc_addr,
                    lnd_tls_cert,
                    lnd_macaroon,
                } => LightningReconnectPayload {
                    node_type: Some(LightningMode::Lnd {
                        lnd_rpc_addr,
                        lnd_tls_cert,
                        lnd_macaroon,
                    }),
                },
            };
            let response = client
                .reconnect(source_password(cli.rpcpassword), payload)
                .await?;
            print_response(response).await;
        }
    }

    Ok(())
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
                println!("\n{formatted}")
            }
        }
        _ => {
            eprintln!("\nError: {}", &response.text().await.unwrap());
            exit(1)
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
