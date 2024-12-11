use anyhow::Context;
use clap::Subcommand;
use fedimint_core::config::FederationId;
use fedimint_core::fedimint_build_code_version_env;
use fedimint_eventlog::{EventKind, EventLogId};
use fedimint_lnv2_common::gateway_api::PaymentFee;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{
    ConfigPayload, ConnectFedPayload, LeaveFedPayload, PaymentLogPayload, SetConfigurationPayload,
};

use crate::print_response;

#[derive(Clone)]
pub struct PerFederationFees {
    federation_id: FederationId,
    fees: PaymentFee,
}

impl std::str::FromStr for PerFederationFees {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(',');
        let federation_id = parts.next().context("Missing federation ID")?.parse()?;
        let base = parts
            .next()
            .context("missing base fee in millisatoshis")?
            .parse()?;
        let parts_per_million = parts.next().context("missing parts per million")?.parse()?;
        Ok(Self {
            federation_id,
            fees: PaymentFee {
                base,
                parts_per_million,
            },
        })
    }
}

impl From<PerFederationFees> for (FederationId, PaymentFee) {
    fn from(val: PerFederationFees) -> Self {
        (val.federation_id, val.fees)
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
        num_route_hints: Option<u32>,

        #[clap(long)]
        network: Option<bitcoin::Network>,

        /// Format federation id,base msat,proportional to millionths part. Any
        /// other federations not given here will keep their current fees.
        #[clap(long)]
        per_federation_routing_fees: Option<Vec<PerFederationFees>>,

        /// Format federation id,base msat,proportional to millionths part. Any
        /// other federations not given here will keep their current fees.
        #[clap(long)]
        per_federation_transaction_fees: Option<Vec<PerFederationFees>>,
    },
    /// Safely stop the gateway
    Stop,
    /// List the transactions that the gateway has processed
    PaymentLog {
        #[clap(long)]
        end_position: Option<EventLogId>,

        #[clap(long, default_value_t = 25)]
        pagination_size: usize,

        #[clap(long)]
        federation_id: FederationId,

        #[clap(long)]
        event_kinds: Vec<EventKind>,
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
                num_route_hints,
                network,
                per_federation_routing_fees,
                per_federation_transaction_fees,
            } => {
                let per_federation_routing_fees = per_federation_routing_fees
                    .map(|input| input.into_iter().map(Into::into).collect());
                let per_federation_transaction_fees = per_federation_transaction_fees
                    .map(|input| input.into_iter().map(Into::into).collect());
                create_client()
                    .set_configuration(SetConfigurationPayload {
                        num_route_hints,
                        network,
                        per_federation_routing_fees,
                        per_federation_transaction_fees,
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
            Self::PaymentLog {
                end_position,
                pagination_size,
                federation_id,
                event_kinds,
            } => {
                let payment_log = create_client()
                    .payment_log(PaymentLogPayload {
                        end_position,
                        pagination_size,
                        federation_id,
                        event_kinds,
                    })
                    .await?;
                print_response(payment_log);
            }
        }

        Ok(())
    }
}
