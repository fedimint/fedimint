use std::time::{Duration, UNIX_EPOCH};

use clap::Subcommand;
use fedimint_core::config::FederationId;
use fedimint_core::time::now;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, fedimint_build_code_version_env};
use fedimint_eventlog::{EventKind, EventLogId};
use fedimint_gateway_client::{
    connect_federation, create_user, delete_user, get_balances, get_info, get_invite_codes,
    get_mnemonic, get_user, leave_federation, list_users, payment_log, payment_summary, stop,
};
use fedimint_gateway_common::{
    ConnectFedPayload, CreateUserPayload, LeaveFedPayload, PaymentLogPayload,
    PaymentSummaryPayload, UserAuthorization,
};
use fedimint_ln_common::client::GatewayApi;

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
    /// List the fedimint transactions that the gateway has processed
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
    /// Create a bcrypt hash of a password, for use in gateway deployment
    CreatePasswordHash {
        password: String,

        /// The bcrypt cost factor to use when hashing the password
        #[clap(long)]
        cost: Option<u32>,
    },
    /// List a payment summary for the last day
    PaymentSummary {
        #[clap(long)]
        start: Option<u64>,

        #[clap(long)]
        end: Option<u64>,
    },
    /// List all invite codes of each federation the gateway has joined
    InviteCodes,
    /// Manage gateway users
    #[command(subcommand)]
    User(UserCommands),
}

/// Commands for managing gateway users (admin only)
#[derive(Subcommand)]
pub enum UserCommands {
    /// Create a new user (admin only)
    Create {
        /// Username (alphanumeric and underscores only, 1-64 characters)
        username: String,

        /// Password for the new user (will be hashed locally before sending to
        /// server)
        #[clap(long)]
        password: String,

        /// Optional description for the user
        #[clap(long)]
        description: Option<String>,

        /// Maximum amount the user can send in a single payment (in msats).
        /// If specified, adds a `SendLimit` authorization.
        #[clap(long)]
        send_limit_msats: Option<u64>,

        /// Allow the user to join and leave federations
        #[clap(long)]
        federation_management: bool,

        /// Allow the user to modify fees
        #[clap(long)]
        fee_management: bool,

        /// Allow the user to open and close lightning channels
        #[clap(long)]
        channel_management: bool,
    },
    /// Delete a user
    Delete {
        /// Username to delete
        username: String,
    },
    /// List all users
    List,
    /// Get details about a specific user
    Get {
        /// Username to look up
        username: String,
    },
}

impl GeneralCommands {
    #[allow(clippy::too_many_lines)]
    pub async fn handle(self, client: &GatewayApi, base_url: &SafeUrl) -> anyhow::Result<()> {
        match self {
            Self::VersionHash => {
                println!("{}", fedimint_build_code_version_env!());
            }
            Self::Info => {
                let response = get_info(client, base_url).await?;
                print_response(response);
            }
            Self::GetBalances => {
                let response = get_balances(client, base_url).await?;
                print_response(response);
            }
            Self::ConnectFed {
                invite_code,
                #[cfg(feature = "tor")]
                use_tor,
                recover,
            } => {
                let response = connect_federation(
                    client,
                    base_url,
                    ConnectFedPayload {
                        invite_code,
                        #[cfg(feature = "tor")]
                        use_tor,
                        #[cfg(not(feature = "tor"))]
                        use_tor: None,
                        recover,
                    },
                )
                .await?;

                print_response(response);
            }
            Self::LeaveFed { federation_id } => {
                let response =
                    leave_federation(client, base_url, LeaveFedPayload { federation_id }).await?;
                print_response(response);
            }
            Self::Seed => {
                let response = get_mnemonic(client, base_url).await?;
                print_response(response);
            }
            Self::Stop => {
                stop(client, base_url).await?;
            }
            Self::PaymentLog {
                end_position,
                pagination_size,
                federation_id,
                event_kinds,
            } => {
                let payment_log = payment_log(
                    client,
                    base_url,
                    PaymentLogPayload {
                        end_position,
                        pagination_size,
                        federation_id,
                        event_kinds,
                    },
                )
                .await?;
                print_response(payment_log);
            }
            Self::CreatePasswordHash { password, cost } => print_response(
                bcrypt::hash(password, cost.unwrap_or(bcrypt::DEFAULT_COST))
                    .expect("Unable to create bcrypt hash"),
            ),
            Self::PaymentSummary { start, end } => {
                let now = now();
                let now_millis = now
                    .duration_since(UNIX_EPOCH)
                    .expect("Before unix epoch")
                    .as_millis()
                    .try_into()?;
                let one_day_ago = now
                    .checked_sub(Duration::from_hours(24))
                    .expect("Before unix epoch");
                let one_day_ago_millis = one_day_ago
                    .duration_since(UNIX_EPOCH)
                    .expect("Before unix epoch")
                    .as_millis()
                    .try_into()?;
                let end_millis = end.unwrap_or(now_millis);
                let start_millis = start.unwrap_or(one_day_ago_millis);
                let payment_summary = payment_summary(
                    client,
                    base_url,
                    PaymentSummaryPayload {
                        start_millis,
                        end_millis,
                    },
                )
                .await?;
                print_response(payment_summary);
            }
            Self::InviteCodes => {
                let invite_codes = get_invite_codes(client, base_url).await?;
                print_response(invite_codes);
            }
            Self::User(user_command) => {
                user_command.handle(client, base_url).await?;
            }
        }

        Ok(())
    }
}

impl UserCommands {
    pub async fn handle(self, client: &GatewayApi, base_url: &SafeUrl) -> anyhow::Result<()> {
        match self {
            Self::Create {
                username,
                password,
                description,
                send_limit_msats,
                federation_management,
                fee_management,
                channel_management,
            } => {
                // Hash the password locally using bcrypt before sending to server
                let password_hash =
                    bcrypt::hash(&password, bcrypt::DEFAULT_COST).expect("Failed to hash password");

                // Build authorizations from flags
                let mut authorizations = Vec::new();
                if let Some(max_msats) = send_limit_msats {
                    authorizations.push(UserAuthorization::SendLimit {
                        max_send_amount: Amount::from_msats(max_msats),
                    });
                }
                if federation_management {
                    authorizations.push(UserAuthorization::FederationManagement);
                }
                if fee_management {
                    authorizations.push(UserAuthorization::FeeManagement);
                }
                if channel_management {
                    authorizations.push(UserAuthorization::ChannelManagement);
                }

                let response = create_user(
                    client,
                    base_url,
                    CreateUserPayload {
                        username,
                        password_hash,
                        description,
                        authorizations,
                    },
                )
                .await?;
                print_response(response);
            }
            Self::Delete { username } => {
                let response = delete_user(client, base_url, &username).await?;
                if response.deleted {
                    println!("User '{username}' deleted successfully");
                } else {
                    println!("User '{username}' not found");
                }
            }
            Self::List => {
                let response = list_users(client, base_url).await?;
                print_response(response);
            }
            Self::Get { username } => {
                let response = get_user(client, base_url, &username).await?;
                match response {
                    Some(user) => print_response(user),
                    None => println!("User '{username}' not found"),
                }
            }
        }

        Ok(())
    }
}
