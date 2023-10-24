use std::str::FromStr;

use clap::Args;
use nostr_sdk::prelude::*;

use crate::utils::{create_client, handle_keys, parse_key};

#[derive(Args, Debug, Clone)]
pub struct ReactionSubCommand {
    /// Event id to react to
    #[arg(short, long)]
    event_id: String,
    /// Author pubkey of the event you are reacting to. Both hex and bech32
    /// encoded keys are supported.
    #[arg(short, long)]
    author_pubkey: String,
    /// Reaction content. Set to '+' for like or '-' for dislike. Single emojis
    /// are also often used for reactions, such as in Damus Web.
    #[arg(short, long)]
    reaction: String,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn react_to_event(
    private_key: Option<String>,
    relays: Vec<String>,
    difficulty_target: u8,
    sub_command_args: &ReactionSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // if sub_command_args.reaction.trim().is_empty() {
    //     panic!("Reaction does not contain any content")
    // }

    // let event_id = EventId::from_hex(&sub_command_args.event_id)?;
    // let author_pubkey_hex =
    // parse_key(sub_command_args.author_pubkey.clone())?; let pubkey =
    // XOnlyPublicKey::from_str(&author_pubkey_hex)?;

    // let id = client.reaction(event_id, pubkey,
    // sub_command_args.reaction.clone())?; println!(
    //     "Reacted to {} with {} in event {}",
    //     event_id.to_bech32()?,
    //     sub_command_args.reaction,
    //     id.to_bech32()?
    // );
    // Ok(())
}
