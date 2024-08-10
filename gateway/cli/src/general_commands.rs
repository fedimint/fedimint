use anyhow::bail;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use clap::Subcommand;
use fedimint_core::config::FederationId;
use fedimint_core::{fedimint_build_code_version_env, Amount, BitcoinAmountOrAll};
use fedimint_mint_client::OOBNotes;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{
    BackupPayload, BalancePayload, ConfigPayload, ConnectFedPayload, DepositAddressPayload,
    FederationRoutingFees, LeaveFedPayload, ReceiveEcashPayload, RestorePayload,
    SetConfigurationPayload, SpendEcashPayload, WithdrawPayload,
};
use tracing::info;

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
    /// Generate a new peg-in address to a federation that the gateway can claim
    /// e-cash for later.
    Address {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Claim funds from a gateway federation to an on-chain address.
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
    /// Register the gateway with a federation.
    ConnectFed {
        /// Invite code to connect to the federation
        invite_code: String,
    },
    /// Leave a federation.
    LeaveFed {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Make a backup of snapshot of all e-cash.
    Backup {
        #[clap(long)]
        federation_id: FederationId,
    },
    /// Restore e-cash from last available snapshot or from scratch.
    Restore {
        #[clap(long)]
        federation_id: FederationId,
    },
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
    /// Spend e-cash
    SpendEcash {
        #[clap(long)]
        federation_id: FederationId,
        amount: Amount,
        #[clap(long)]
        allow_overpay: bool,
        #[clap(long, default_value_t = 60 * 60 * 24 * 7)]
        timeout: u64,
        #[clap(long)]
        include_invite: bool,
    },
    /// Receive e-cash
    ReceiveEcash {
        #[clap(long)]
        notes: OOBNotes,
        #[arg(long = "no-wait", action = clap::ArgAction::SetFalse)]
        wait: bool,
    },
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
            Self::Address { federation_id } => {
                let response = create_client()
                    .get_deposit_address(DepositAddressPayload { federation_id })
                    .await?;

                print_response(response);
            }
            Self::Withdraw {
                federation_id,
                amount,
                address,
            } => {
                let response = create_client()
                    .withdraw(WithdrawPayload {
                        federation_id,
                        amount,
                        address,
                    })
                    .await?;

                print_response(response);
            }
            Self::ConnectFed { invite_code } => {
                let response = create_client()
                    .connect_federation(ConnectFedPayload { invite_code })
                    .await?;

                print_response(response);
            }
            Self::LeaveFed { federation_id } => {
                let response = create_client()
                    .leave_federation(LeaveFedPayload { federation_id })
                    .await?;
                print_response(response);
            }
            Self::Backup { federation_id } => {
                create_client()
                    .backup(BackupPayload { federation_id })
                    .await?;
            }
            Self::Restore { federation_id } => {
                create_client()
                    .restore(RestorePayload { federation_id })
                    .await?;
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
            Self::SpendEcash {
                federation_id,
                amount,
                allow_overpay,
                timeout,
                include_invite,
            } => {
                let response = create_client()
                    .spend_ecash(SpendEcashPayload {
                        federation_id,
                        amount,
                        allow_overpay,
                        timeout,
                        include_invite,
                    })
                    .await?;

                print_response(response);
            }
            Self::ReceiveEcash { notes, wait } => {
                let response = create_client()
                    .receive_ecash(ReceiveEcashPayload { notes, wait })
                    .await?;

                print_response(response);
            }
        }

        Ok(())
    }
}
