#![deny(clippy::pedantic, clippy::nursery)]

mod general_commands;
mod lightning_commands;

use clap::{CommandFactory, Parser, Subcommand};
use fedimint_core::util::SafeUrl;
use fedimint_logging::TracingSetup;
use general_commands::GeneralCommands;
use lightning_commands::LightningCommands;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::V1_API_ENDPOINT;
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

fn print_response<T: Serialize>(val: T) {
    println!(
        "{}",
        serde_json::to_string_pretty(&val).expect("Cannot serialize")
    );
}
