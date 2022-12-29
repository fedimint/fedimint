use std::{net::SocketAddr, path::PathBuf};

use bitcoin::{Address, Amount, Transaction};
use clap::{Parser, Subcommand};
use fedimint_server::modules::wallet::txoproof::TxOutProof;
use ln_gateway::{
    config::{ClnRpcConfig, GatewayConfig, LndRpcConfig},
    rpc::{
        rpc_client::RpcClient, BalancePayload, ConnectFedPayload, ConnectLnPayload,
        DepositAddressPayload, DepositPayload, WithdrawPayload,
    },
};
use mint_client::{utils::from_hex, FederationId};
use url::Url;

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The address of the gateway webserver
    #[clap(short, long, default_value = "http://127.0.0.1:8080")]
    address: Url,
    #[command(subcommand)]
    command: Commands,
    /// WARNING: Passing in a password from the command line may be less secure!
    #[clap(long)]
    rpcpassword: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    // Ganerate lnrpc configuration
    GenerateLnrpcConfig {
        /// The lnrpc configuration directory
        out_dir: PathBuf,
        lnrpc_bind_address: SocketAddr,
        node_host: Option<String>,
        node_port: Option<u32>,
        tls_cert_path: Option<String>,
        macaroon_path: Option<String>,
    },
    /// Ganerate gateway configuration
    /// NOTE: This command can only be used on a local gateway
    GenerateGatewayConfig {
        /// The gateway configuration directory
        out_dir: PathBuf,
        /// Address to which the API webserver will bind
        api_bind_address: SocketAddr,
        /// URL under which the API will be reachable
        api_announce_address: Url,
    },
    /// Display CLI version hash
    VersionHash,
    /// Display high-level information about the Gateway
    Info,
    /// Check gateway balance
    Balance { federation_id: FederationId },
    /// Generate a new peg-in address, funds sent to it can later be claimed
    Address { federation_id: FederationId },
    /// Deposit funds into a gateway federation
    Deposit {
        federation_id: FederationId,
        /// The TxOutProof which was created from sending BTC to the pegin-address
        #[clap(value_parser = from_hex::<TxOutProof>)]
        txout_proof: TxOutProof,
        #[clap(value_parser = from_hex::<Transaction>)]
        transaction: Transaction,
    },
    /// Claim funds from a gateway federation
    Withdraw {
        federation_id: FederationId,
        /// The amount to withdraw
        amount: Amount,
        /// The address to send the funds to
        address: Address,
    },
    /// Connect a lightning rpc with the gateway
    ConnectLn {
        /// Socket address of the gateway lightning rpc server
        address: SocketAddr,
    },
    /// Connect a federation with the gateway
    ConnectFed {
        /// ConnectInfo code to connect to the federation
        connect: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = RpcClient::new(cli.address);

    match cli.command {
        Commands::GenerateLnrpcConfig {
            lnrpc_bind_address,
            node_host,
            node_port,
            tls_cert_path,
            macaroon_path,
            mut out_dir,
        } => {
            // Recursively create config directory if it doesn't exist
            std::fs::create_dir_all(&out_dir).expect("Failed to create config directory");
            // Create config file
            out_dir.push("lnrpc.config");

            let cfg_file =
                std::fs::File::create(out_dir).expect("Failed to create gateway config file");
            if node_host.is_some()
                && node_port.is_some()
                && tls_cert_path.is_some()
                && macaroon_path.is_some()
            {
                serde_json::to_writer_pretty(
                    cfg_file,
                    &LndRpcConfig {
                        lnrpc_bind_address,
                        node_host: node_host.unwrap(),
                        node_port: node_port.unwrap(),
                        tls_cert_path: tls_cert_path.unwrap(),
                        macaroon_path: macaroon_path.unwrap(),
                    },
                )
                .expect("Failed to write LND lnrpc configs to file");
            } else {
                serde_json::to_writer_pretty(cfg_file, &ClnRpcConfig { lnrpc_bind_address })
                    .expect("Failed to write CLN lnrpc configs to file");
            }
        }
        Commands::GenerateGatewayConfig {
            api_bind_address,
            api_announce_address,
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
                    api_bind_address,
                    api_announce_address,
                    webserver_password: source_password(cli.rpcpassword), // TODO: Generate a strong random password
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
        Commands::ConnectLn { address } => {
            let response = client
                .connect_lightning(
                    source_password(cli.rpcpassword),
                    ConnectLnPayload { address },
                )
                .await
                .expect("Failed to connect lightning rpc");

            print_response(response).await;
        }
        Commands::ConnectFed { connect } => {
            let response = client
                .connect_federation(
                    source_password(cli.rpcpassword),
                    ConnectFedPayload { connect },
                )
                .await
                .expect("Failed to connect federation");

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
