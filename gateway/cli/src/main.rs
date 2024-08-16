#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]

use std::time::Duration;

use anyhow::bail;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use clap::{CommandFactory, Parser, Subcommand};
use fedimint_core::config::FederationId;
use fedimint_core::util::{backoff_util, retry, SafeUrl};
use fedimint_core::{fedimint_build_code_version_env, BitcoinAmountOrAll};
use fedimint_logging::TracingSetup;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{
    BackupPayload, BalancePayload, CloseChannelsWithPeerPayload, ConfigPayload, ConnectFedPayload,
    DepositAddressPayload, FederationRoutingFees, GetFundingAddressPayload, LeaveFedPayload,
    OpenChannelPayload, RestorePayload, SetConfigurationPayload, WithdrawPayload, V1_API_ENDPOINT,
};
use serde::Serialize;

const DEFAULT_WAIT_FOR_CHAIN_SYNC_RETRIES: u32 = 60;
const DEFAULT_WAIT_FOR_CHAIN_SYNC_RETRY_DELAY_SECONDS: u64 = 2;

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The address of the gateway webserver
    #[clap(short, long, default_value = "http://127.0.0.1:8175")]
    address: SafeUrl,
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
    /// Display config information about the Gateways federation
    Config {
        #[clap(long)]
        federation_id: Option<FederationId>,
    },
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
    /// Claim funds from a gateway federation
    Withdraw {
        #[clap(long)]
        federation_id: FederationId,
        /// The amount to withdraw
        #[clap(long)]
        amount: BitcoinAmountOrAll,
        /// The address to send the funds to
        #[clap(long)]
        address: Address<NetworkUnchecked>,
    },
    /// Register federation with the gateway
    ConnectFed {
        /// InviteCode code to connect to the federation
        invite_code: String,
    },
    /// Leave a federation
    LeaveFed {
        #[clap(long)]
        federation_id: FederationId,
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
    Completion {
        shell: clap_complete::Shell,
    },
    SetConfiguration {
        #[clap(long)]
        password: Option<String>,

        #[clap(long)]
        num_route_hints: Option<u32>,

        /// Default routing fee for all new federations. Setting it won't affect
        /// existing federations
        #[clap(long)]
        routing_fees: Option<FederationRoutingFees>,

        #[clap(long)]
        network: Option<bitcoin::Network>,

        /// Format federation id,base msat,proportional to millionths part. Any
        /// other federations not given here will keep their current fees.
        #[clap(long)]
        per_federation_routing_fees: Option<Vec<PerFederationRoutingFees>>,
    },
    #[command(subcommand)]
    Lightning(LightningCommands),
}

/// This API is intentionally kept very minimal, as its main purpose is to
/// provide a simple and consistent way to establish liquidity between gateways
/// in a test environment.
#[derive(Subcommand)]
pub enum LightningCommands {
    /// Get a Bitcoin address to fund the gateway
    GetFundingAddress,
    /// Open a channel with another lightning node
    OpenChannel {
        /// The public key of the node to open a channel with
        #[clap(long)]
        pubkey: bitcoin::secp256k1::PublicKey,

        #[clap(long)]
        host: String,

        /// The amount to fund the channel with
        #[clap(long)]
        channel_size_sats: u64,

        /// The amount to push to the other side of the channel
        #[clap(long)]
        push_amount_sats: Option<u64>,
    },
    /// Close all channels with a peer, claiming the funds to the lightning
    /// node's on-chain wallet
    CloseChannelsWithPeer {
        // The public key of the node to close channels with
        #[clap(long)]
        pubkey: bitcoin::secp256k1::PublicKey,
    },
    /// List active channels
    ListActiveChannels,
    /// Wait for the lightning node to be synced with the blockchain
    WaitForChainSync {
        /// The block height to wait for
        #[clap(long)]
        block_height: u32,

        /// The maximum number of retries
        #[clap(long)]
        max_retries: Option<u32>,

        /// The delay between retries
        #[clap(long)]
        retry_delay_seconds: Option<u64>,
    },
}

#[derive(Clone)]
pub struct PerFederationRoutingFees {
    pub federation_id: FederationId,
    pub routing_fees: FederationRoutingFees,
}

impl std::str::FromStr for PerFederationRoutingFees {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((federation_id, rounting_fees)) = s.split_once(',') {
            Ok(PerFederationRoutingFees {
                federation_id: federation_id.parse()?,
                routing_fees: rounting_fees.parse()?,
            })
        } else {
            bail!("Wrong format, please provide: <federation id>,<base msat>,<proportional to millionths part>");
        }
    }
}

impl From<PerFederationRoutingFees> for (FederationId, FederationRoutingFees) {
    fn from(val: PerFederationRoutingFees) -> Self {
        (val.federation_id, val.routing_fees)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli = Cli::parse();
    let versioned_api = cli.address.join(V1_API_ENDPOINT)?;
    let client = || GatewayRpcClient::new(versioned_api.clone(), cli.rpcpassword.clone());

    match cli.command {
        Commands::VersionHash => {
            println!("{}", fedimint_build_code_version_env!());
        }
        Commands::Info => {
            // For backwards-compatibility, fallback to the original POST endpoint if the
            // GET endpoint fails
            // FIXME: deprecated >= 0.3.0
            let response = match client().get_info().await {
                Ok(res) => res,
                Err(_) => client().get_info_legacy().await?,
            };

            print_response(response);
        }

        Commands::Config { federation_id } => {
            let response = client().get_config(ConfigPayload { federation_id }).await?;

            print_response(response);
        }
        Commands::Balance { federation_id } => {
            let response = client()
                .get_balance(BalancePayload { federation_id })
                .await?;

            print_response(response);
        }
        Commands::Address { federation_id } => {
            let response = client()
                .get_deposit_address(DepositAddressPayload { federation_id })
                .await?;

            print_response(response);
        }
        Commands::Withdraw {
            federation_id,
            amount,
            address,
        } => {
            let response = client()
                .withdraw(WithdrawPayload {
                    federation_id,
                    amount,
                    address,
                })
                .await?;

            print_response(response);
        }
        Commands::ConnectFed { invite_code } => {
            let response = client()
                .connect_federation(ConnectFedPayload { invite_code })
                .await?;

            print_response(response);
        }
        Commands::LeaveFed { federation_id } => {
            let response = client()
                .leave_federation(LeaveFedPayload { federation_id })
                .await?;
            print_response(response);
        }
        Commands::Backup { federation_id } => {
            client().backup(BackupPayload { federation_id }).await?;
        }
        Commands::Restore { federation_id } => {
            client().restore(RestorePayload { federation_id }).await?;
        }
        Commands::Completion { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "gateway-cli",
                &mut std::io::stdout(),
            );
        }
        Commands::SetConfiguration {
            password,
            num_route_hints,
            routing_fees,
            network,
            per_federation_routing_fees,
        } => {
            let per_federation_routing_fees = per_federation_routing_fees
                .map(|input| input.into_iter().map(Into::into).collect());
            client()
                .set_configuration(SetConfigurationPayload {
                    password,
                    num_route_hints,
                    routing_fees,
                    network,
                    per_federation_routing_fees,
                })
                .await?;
        }

        Commands::Lightning(lightning_command) => match lightning_command {
            LightningCommands::GetFundingAddress => {
                let response = client()
                    .get_funding_address(GetFundingAddressPayload {})
                    .await?
                    .require_network();
                println!("{response}");
            }
            LightningCommands::OpenChannel {
                pubkey,
                host,
                channel_size_sats,
                push_amount_sats,
            } => {
                client()
                    .open_channel(OpenChannelPayload {
                        pubkey,
                        host,
                        channel_size_sats,
                        push_amount_sats: push_amount_sats.unwrap_or(0),
                    })
                    .await?;
            }
            LightningCommands::CloseChannelsWithPeer { pubkey } => {
                let response = client()
                    .close_channels_with_peer(CloseChannelsWithPeerPayload { pubkey })
                    .await?;
                print_response(response);
            }
            LightningCommands::ListActiveChannels => {
                let response = client().list_active_channels().await?;
                print_response(response);
            }
            LightningCommands::WaitForChainSync {
                block_height,
                max_retries,
                retry_delay_seconds,
            } => {
                let retry_duration = Duration::from_secs(
                    retry_delay_seconds.unwrap_or(DEFAULT_WAIT_FOR_CHAIN_SYNC_RETRY_DELAY_SECONDS),
                );

                retry(
                    "Wait for chain sync",
                    backoff_util::custom_backoff(
                        retry_duration,
                        retry_duration,
                        Some(max_retries.unwrap_or(DEFAULT_WAIT_FOR_CHAIN_SYNC_RETRIES) as usize),
                    ),
                    || async {
                        let info = client().get_info().await?;
                        if info.block_height.unwrap_or(0) >= block_height && info.synced_to_chain {
                            Ok(())
                        } else {
                            Err(anyhow::anyhow!("Not synced yet"))
                        }
                    },
                )
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for chain sync"))?;
            }
        },
    }

    Ok(())
}

pub fn print_response<T: Serialize>(val: T) {
    println!(
        "{}",
        serde_json::to_string_pretty(&val).expect("Cannot serialize")
    );
}
