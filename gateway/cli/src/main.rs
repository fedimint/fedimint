use bitcoin::{Address, Amount, Transaction};
use clap::{Parser, Subcommand};
use fedimint_client_legacy::utils::from_hex;
use fedimint_core::config::FederationId;
use fedimint_core::txoproof::TxOutProof;
use fedimint_logging::TracingSetup;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload,
    RestorePayload, WithdrawPayload,
};
use serde::Serialize;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli = Cli::parse();
    let client = GatewayRpcClient::new(cli.address, source_password(cli.rpcpassword));

    match cli.command {
        Commands::VersionHash => {
            println!("version: {}", env!("CODE_VERSION"));
        }
        Commands::Info => {
            let response = client.get_info().await?;

            print_response(response).await;
        }
        Commands::Balance { federation_id } => {
            let response = client.get_balance(BalancePayload { federation_id }).await?;

            print_response(response).await;
        }
        Commands::Address { federation_id } => {
            let response = client
                .get_deposit_address(DepositAddressPayload { federation_id })
                .await?;

            print_response(response).await;
        }
        Commands::Deposit {
            federation_id,
            txout_proof,
            transaction,
        } => {
            let response = client
                .deposit(DepositPayload {
                    federation_id,
                    txout_proof,
                    transaction,
                })
                .await?;

            print_response(response).await;
        }
        Commands::Withdraw {
            federation_id,
            amount,
            address,
        } => {
            let response = client
                .withdraw(WithdrawPayload {
                    federation_id,
                    amount,
                    address,
                })
                .await?;

            print_response(response).await;
        }
        Commands::ConnectFed { connect } => {
            let response = client
                .connect_federation(ConnectFedPayload { connect })
                .await?;

            print_response(response).await;
        }
        Commands::Backup { federation_id } => {
            client.backup(BackupPayload { federation_id }).await?;
        }
        Commands::Restore { federation_id } => {
            client.restore(RestorePayload { federation_id }).await?;
        }
    }

    Ok(())
}

pub async fn print_response<T: Serialize>(val: T) {
    println!(
        "{}",
        serde_json::to_string_pretty(&val).expect("Cannot serialize")
    )
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
