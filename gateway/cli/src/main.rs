use anyhow::bail;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use clap::{CommandFactory, Parser, Subcommand};
use fedimint_core::bitcoin_migration::{
    bitcoin30_to_bitcoin29_address, bitcoin30_to_bitcoin29_network,
};
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{fedimint_build_code_version_env, BitcoinAmountOrAll};
use fedimint_logging::TracingSetup;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{
    BackupPayload, BalancePayload, ConfigPayload, ConnectFedPayload, DepositAddressPayload,
    FederationRoutingFees, LeaveFedPayload, RestorePayload, SetConfigurationPayload,
    WithdrawPayload, V1_API_ENDPOINT,
};
use serde::Serialize;

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
        routing_fees: Option<String>,

        #[clap(long)]
        network: Option<bitcoin::Network>,

        /// Format federation id,base msat,proportional to millionths part. Any
        /// other federations not given here will keep their current fees.
        #[clap(long)]
        per_federation_routing_fees: Option<Vec<PerFederationRoutingFees>>,
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

            print_response(response).await;
        }

        Commands::Config { federation_id } => {
            let response = client().get_config(ConfigPayload { federation_id }).await?;

            print_response(response).await;
        }
        Commands::Balance { federation_id } => {
            let response = client()
                .get_balance(BalancePayload { federation_id })
                .await?;

            print_response(response).await;
        }
        Commands::Address { federation_id } => {
            let response = client()
                .get_deposit_address(DepositAddressPayload { federation_id })
                .await?;

            print_response(response).await;
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
                    address: bitcoin30_to_bitcoin29_address(address.assume_checked()),
                })
                .await?;

            print_response(response).await;
        }
        Commands::ConnectFed { invite_code } => {
            let response = client()
                .connect_federation(ConnectFedPayload { invite_code })
                .await?;

            print_response(response).await;
        }
        Commands::LeaveFed { federation_id } => {
            let response = client()
                .leave_federation(LeaveFedPayload { federation_id })
                .await?;
            print_response(response).await;
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
                    network: network.map(bitcoin30_to_bitcoin29_network),
                    routing_fees,
                    per_federation_routing_fees,
                })
                .await?;
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
