use clap::Args;
use nostr_sdk::Result;

use crate::utils::{create_client, handle_keys};

#[derive(Args, Debug, Clone)]
pub struct RecommendRelaySubCommand {
    /// Relay URL to recommend
    #[arg(short, long)]
    url: String,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn recommend_relay(
    private_key: Option<String>,
    relays: Vec<String>,
    difficulty_target: u8,
    sub_command_args: &RecommendRelaySubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // client.add_recommended_relay(sub_command_args.url.clone())?;
    // println!("Relay {} recommended", sub_command_args.url);

    // Ok(())
}
