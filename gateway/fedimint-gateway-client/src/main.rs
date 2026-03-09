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

/// Type alias for CLI command results
pub type CliOutputResult = anyhow::Result<CliOutput>;

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
        eprintln!("Failed to initialize logging: {err}");
        std::process::exit(1);
    }

    if let Err(err) = run().await {
        eprintln!("Error: {err}");
        let mut source = err.source();
        eprintln!("Caused by");
        while let Some(err) = source {
            eprintln!("    {err}");
            source = err.source();
        }
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let connector_registry = ConnectorRegistry::build_from_client_defaults()
        .with_env_var_overrides()?
        .bind()
        .await?;
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
            return Ok(());
        }
    };

    // Only print output for non-empty results
    if !matches!(output, CliOutput::Empty) {
        print_response(output);
    }

    Ok(())
}

fn print_response<T: Serialize>(val: T) {
    println!(
        "{}",
        serde_json::to_string_pretty(&val).expect("Cannot serialize")
    );
}
