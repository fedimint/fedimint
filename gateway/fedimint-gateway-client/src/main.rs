#![deny(clippy::pedantic, clippy::nursery)]

mod config_commands;
mod ecash_commands;
mod general_commands;
mod lightning_commands;
mod onchain_commands;

use std::collections::BTreeMap;

use bitcoin::Txid;
use bitcoin::address::NetworkUnchecked;
use clap::{CommandFactory, Parser, Subcommand};
use config_commands::ConfigCommands;
use ecash_commands::EcashCommands;
use fedimint_connectors::ConnectorRegistry;
use fedimint_connectors::error::ServerError;
use fedimint_core::PeerId;
use fedimint_core::config::FederationId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{
    ChannelInfo, CloseChannelsWithPeerResponse, CreateOfferResponse, FederationConfig,
    FederationInfo, GatewayBalances, GatewayFedConfig, GatewayInfo, GetInvoiceResponse,
    ListTransactionsResponse, MnemonicResponse, PayOfferResponse, PaymentLogResponse,
    PaymentSummaryResponse, ReceiveEcashResponse, SpendEcashResponse, WithdrawResponse,
};
use fedimint_ln_common::client::GatewayApi;
use fedimint_logging::TracingSetup;
use general_commands::GeneralCommands;
use lightning_commands::LightningCommands;
use onchain_commands::OnchainCommands;
use serde::Serialize;

/// Unified output type for all gateway-cli commands.
///
/// This enum uses `#[serde(untagged)]` to serialize each variant directly
/// as its inner type, maintaining backward compatibility with existing
/// JSON output formats while providing type safety in the code.
#[derive(Serialize)]
#[serde(untagged)]
pub enum CliOutput {
    // General commands
    Info(GatewayInfo),
    Balances(GatewayBalances),
    Federation(FederationInfo),
    Mnemonic(MnemonicResponse),
    PaymentLog(PaymentLogResponse),
    PaymentSummary(PaymentSummaryResponse),
    InviteCodes(BTreeMap<FederationId, BTreeMap<PeerId, (String, InviteCode)>>),
    PasswordHash(String),

    // Lightning commands
    Invoice {
        invoice: String,
    },
    Preimage {
        preimage: String,
    },
    FundingTxid {
        funding_txid: Txid,
    },
    Channels(Vec<ChannelInfo>),
    CloseChannels(CloseChannelsWithPeerResponse),
    InvoiceDetails(Option<GetInvoiceResponse>),
    Transactions(ListTransactionsResponse),
    Offer(CreateOfferResponse),
    OfferPayment(PayOfferResponse),

    // Ecash commands
    DepositAddress {
        address: bitcoin::Address<NetworkUnchecked>,
    },
    DepositRecheck(serde_json::Value),
    PeginTxid {
        txid: Txid,
    },
    Withdraw(WithdrawResponse),
    SpendEcash(SpendEcashResponse),
    ReceiveEcash(ReceiveEcashResponse),

    // Onchain commands
    OnchainAddress {
        address: String,
    },
    SendOnchainTxid {
        txid: Txid,
    },

    // Config commands
    Config(GatewayFedConfig),
    FederationConfigs(Vec<FederationConfig>),

    // No output (for commands that succeed silently)
    #[serde(skip)]
    Empty,
}

/// Type alias for CLI command results using `ServerError` for precise error
/// classification
pub type CliOutputResult = Result<CliOutput, ServerError>;

/// Machine-readable error codes for programmatic error handling.
///
/// These codes allow agents and scripts to handle errors programmatically
/// without parsing error message strings.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Authentication failed (wrong password, missing auth)
    AuthFailed,
    /// Could not connect to gateway server
    ConnectionFailed,
    /// Invalid command arguments or request format
    InvalidInput,
    /// Requested resource not found (federation, invoice, etc.)
    NotFound,
    /// Gateway is not in correct state for operation
    InvalidState,
    /// Operation timed out
    Timeout,
    /// Internal gateway or client error
    Internal,
    /// Unknown/unclassified error
    Unknown,
}

/// Exit codes for the CLI process.
///
/// These provide semantic meaning to the exit status, allowing scripts
/// to handle different error categories appropriately.
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    GeneralError = 1,
    ConnectionError = 2,
    AuthError = 3,
    InvalidInput = 4,
    NotFound = 5,
    Timeout = 6,
}

impl From<ErrorCode> for ExitCode {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::AuthFailed => Self::AuthError,
            ErrorCode::ConnectionFailed => Self::ConnectionError,
            ErrorCode::InvalidInput => Self::InvalidInput,
            ErrorCode::NotFound => Self::NotFound,
            ErrorCode::Timeout => Self::Timeout,
            ErrorCode::InvalidState | ErrorCode::Internal | ErrorCode::Unknown => {
                Self::GeneralError
            }
        }
    }
}

/// Structured error type for CLI output.
///
/// This provides machine-readable error information in JSON format,
/// making it easier for agents and scripts to handle errors programmatically.
#[derive(Debug, Serialize)]
pub struct CliError {
    /// Human-readable error message
    pub error: String,

    /// Machine-readable error code for programmatic handling
    pub code: ErrorCode,

    /// The immediate cause of the error, if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

impl CliError {
    /// Create a new `CliError` from a `ServerError`.
    ///
    /// This extracts the error message, classifies the error code,
    /// and captures the immediate cause.
    fn from_server_error(err: &ServerError) -> Self {
        let error = err.to_string();
        let code = Self::classify_server_error(err);
        let cause = std::error::Error::source(err).map(ToString::to_string);

        Self { error, code, cause }
    }

    /// Classify a `ServerError` into an appropriate `ErrorCode`.
    const fn classify_server_error(err: &ServerError) -> ErrorCode {
        match err {
            // Authentication/authorization errors
            ServerError::InvalidRequest(_) => ErrorCode::AuthFailed,

            // Connection and transport errors
            ServerError::Connection(_) | ServerError::Transport(_) => ErrorCode::ConnectionFailed,

            // Invalid input errors
            ServerError::InvalidPeerId { .. }
            | ServerError::InvalidPeerUrl { .. }
            | ServerError::InvalidEndpoint(_)
            | ServerError::InvalidRpcId(_) => ErrorCode::InvalidInput,

            // Internal errors (response parsing, server errors, client errors)
            ServerError::ResponseDeserialization(_)
            | ServerError::InvalidResponse(_)
            | ServerError::ServerError(_)
            | ServerError::InternalClientError(_) => ErrorCode::Internal,

            // Condition failures (often "not found" scenarios)
            ServerError::ConditionFailed(_) => ErrorCode::NotFound,

            // Catch-all for future ServerError variants (enum is non_exhaustive)
            _ => ErrorCode::Unknown,
        }
    }
}

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The address of the gateway webserver
    #[clap(long, short, default_value = "http://127.0.0.1:80")]
    address: SafeUrl,

    /// The command to execute
    #[command(subcommand)]
    command: Commands,

    /// Password for authenticated requests to the gateway
    #[clap(long)]
    rpcpassword: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(flatten)]
    General(GeneralCommands),
    #[command(subcommand)]
    Lightning(LightningCommands),
    #[command(subcommand)]
    Ecash(EcashCommands),
    #[command(subcommand)]
    Onchain(OnchainCommands),
    #[command(subcommand)]
    Cfg(ConfigCommands),
    Completion {
        shell: clap_complete::Shell,
    },
}

#[tokio::main]
async fn main() {
    if let Err(err) = TracingSetup::default().init() {
        let cli_err = CliError {
            error: format!("Failed to initialize logging: {err}"),
            code: ErrorCode::Internal,
            cause: None,
        };
        print_response(&cli_err);
        std::process::exit(ExitCode::GeneralError as i32);
    }

    if let Err(err) = run().await {
        let cli_err = CliError::from_server_error(&err);
        let exit_code = ExitCode::from(cli_err.code);
        print_response(&cli_err);
        std::process::exit(exit_code as i32);
    }
}

async fn run() -> CliOutputResult {
    let cli = Cli::parse();
    let connector_registry = ConnectorRegistry::build_from_client_defaults()
        .with_env_var_overrides()
        .map_err(ServerError::InternalClientError)?
        .bind()
        .await
        .map_err(ServerError::InternalClientError)?;
    let client = GatewayApi::new(cli.rpcpassword, connector_registry);

    let output = match cli.command {
        Commands::General(general_command) => general_command.handle(&client, &cli.address).await?,
        Commands::Lightning(lightning_command) => {
            lightning_command.handle(&client, &cli.address).await?
        }
        Commands::Ecash(ecash_command) => ecash_command.handle(&client, &cli.address).await?,
        Commands::Onchain(onchain_command) => onchain_command.handle(&client, &cli.address).await?,
        Commands::Cfg(config_commands) => config_commands.handle(&client, &cli.address).await?,
        Commands::Completion { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "gateway-cli",
                &mut std::io::stdout(),
            );
            return Ok(CliOutput::Empty);
        }
    };

    // Only print output for non-empty results
    if !matches!(output, CliOutput::Empty) {
        print_response(&output);
    }

    Ok(output)
}

fn print_response<T: Serialize>(val: T) {
    println!(
        "{}",
        serde_json::to_string_pretty(&val).expect("Cannot serialize")
    );
}
