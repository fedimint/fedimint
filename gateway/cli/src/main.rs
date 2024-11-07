#![deny(clippy::pedantic, clippy::nursery)]

mod ecash_commands;
mod general_commands;
mod lightning_commands;
mod onchain_commands;

use clap::{CommandFactory, Parser, Subcommand};
use ecash_commands::EcashCommands;
use fedimint_core::util::SafeUrl;
use fedimint_logging::TracingSetup;
use general_commands::GeneralCommands;
use lightning_commands::LightningCommands;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::V1_API_ENDPOINT;
use onchain_commands::OnchainCommands;
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
enum Commands {
    #[command(flatten)]
    General(GeneralCommands),
    #[command(subcommand)]
    Lightning(LightningCommands),
    #[command(subcommand)]
    Ecash(EcashCommands),
    #[command(subcommand)]
    Onchain(OnchainCommands),
    Completion {
        shell: clap_complete::Shell,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli = Cli::parse();
    let versioned_api = cli.address.join(V1_API_ENDPOINT)?;
    let create_client = || GatewayRpcClient::new(versioned_api.clone(), cli.rpcpassword.clone());

    match cli.command {
        Commands::General(general_command) => general_command.handle(create_client).await?,
        Commands::Lightning(lightning_command) => lightning_command.handle(create_client).await?,
        Commands::Ecash(ecash_command) => ecash_command.handle(create_client).await?,
        Commands::Onchain(onchain_command) => onchain_command.handle(create_client).await?,
        Commands::Completion { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "gateway-cli",
                &mut std::io::stdout(),
            );
        }
    }

    Ok(())
}

fn print_response<T: Serialize>(val: T) {
    println!(
        "{}",
        serde_json::to_string_pretty(&val).expect("Cannot serialize")
    );
}
