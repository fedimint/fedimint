use anyhow::bail;
use clap::Subcommand;
use fedimint_core::config::FederationId;
use fedimint_core::fedimint_build_code_version_env;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{
    BalancePayload, ConfigPayload, ConnectFedPayload, FederationRoutingFees, LeaveFedPayload,
    SetConfigurationPayload,
};

use crate::print_response;

#[derive(Clone)]
pub struct PerFederationRoutingFees {
    federation_id: FederationId,
    routing_fees: FederationRoutingFees,
}

impl std::str::FromStr for PerFederationRoutingFees {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((federation_id, routing_fees)) = s.split_once(',') {
            Ok(Self {
                federation_id: federation_id.parse()?,
                routing_fees: routing_fees.parse()?,
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

#[derive(Subcommand)]
pub enum GeneralCommands {
    /// Display the version hash of the CLI.
    VersionHash,
    /// Display high-level information about the gateway.
    Info,
    /// Display config information about the federation(s) the gateway is
    /// connected to.
    Config {
        #[clap(long)]
        federation_id: Option<FederationId>,
    },
    /// Check gateway's e-cash balance on the specified federation.
    Balance {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Get the total on-chain, lightning, and eCash balances of the gateway.
    GetBalances,
    /// Register the gateway with a federation.
    ConnectFed {
        /// Invite code to connect to the federation
        invite_code: String,
        /// Activate usage of Tor (or not) as the connector for the federation
        /// client
        #[cfg(feature = "tor")]
        use_tor: Option<bool>,
        /// Indicates if the client should be recovered from a mnemonic
        #[clap(long)]
        recover: Option<bool>,
    },
    /// Leave a federation.
    LeaveFed {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Prints the seed phrase for the gateway
    Seed,
    /// Set or update the gateway configuration.
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
    /// Safely stop the gateway
    Stop,
}

impl GeneralCommands {
    #[allow(clippy::too_many_lines)]
    pub async fn handle(
        self,
        create_client: impl Fn() -> GatewayRpcClient + Send + Sync,
    ) -> anyhow::Result<()> {
        match self {
            Self::VersionHash => {
                println!("{}", fedimint_build_code_version_env!());
            }
            Self::Info => {
                // For backwards-compatibility, fallback to the original POST endpoint if the
                // GET endpoint fails
                // FIXME: deprecated >= 0.3.0
                let client = create_client();
                let response = match client.get_info().await {
                    Ok(res) => res,
                    Err(_) => client.get_info_legacy().await?,
                };

                print_response(response);
            }

            Self::Config { federation_id } => {
                let response = create_client()
                    .get_config(ConfigPayload { federation_id })
                    .await?;

                print_response(response);
            }
            Self::Balance { federation_id } => {
                let response = create_client()
                    .get_balance(BalancePayload { federation_id })
                    .await?;

                print_response(response);
            }
            Self::GetBalances => {
                let response = create_client().get_balances().await?;
                print_response(response);
            }
            Self::ConnectFed {
                invite_code,
                #[cfg(feature = "tor")]
                use_tor,
                recover,
            } => {
                let response = create_client()
                    .connect_federation(ConnectFedPayload {
                        invite_code,
                        #[cfg(feature = "tor")]
                        use_tor,
                        recover,
                    })
                    .await?;

                print_response(response);
            }
            Self::LeaveFed { federation_id } => {
                let response = create_client()
                    .leave_federation(LeaveFedPayload { federation_id })
                    .await?;
                print_response(response);
            }
            Self::SetConfiguration {
                password,
                num_route_hints,
                routing_fees,
                network,
                per_federation_routing_fees,
            } => {
                let per_federation_routing_fees = per_federation_routing_fees
                    .map(|input| input.into_iter().map(Into::into).collect());
                create_client()
                    .set_configuration(SetConfigurationPayload {
                        password,
                        num_route_hints,
                        routing_fees,
                        network,
                        per_federation_routing_fees,
                    })
                    .await?;
            }
            Self::Seed => {
                let response = create_client().get_mnemonic().await?;
                print_response(response);
            }
            Self::Stop => {
                create_client().stop().await?;
            }
        }

        Ok(())
    }
}
