use clap::Subcommand;
use fedimint_core::config::FederationId;
use fedimint_core::fedimint_build_code_version_env;
use fedimint_eventlog::{EventKind, EventLogId};
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{ConnectFedPayload, LeaveFedPayload, PaymentLogPayload};

use crate::print_response;

#[derive(Subcommand)]
pub enum GeneralCommands {
    /// Display the version hash of the CLI.
    VersionHash,
    /// Display high-level information about the gateway.
    Info,
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
    /// request a JWT token for future interactions
    GetSessionJwtAuth,
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
            Self::GetSessionJwtAuth => {
                let response = create_client().get_session_jwt_auth().await?;
                print_response(response);
            }
        }
        Ok(())
    }
}
