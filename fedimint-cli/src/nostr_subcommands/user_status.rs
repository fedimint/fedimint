use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;

use clap::Args;
use nostr_sdk::prelude::*;

use crate::utils::{create_client, handle_keys, parse_key};

#[derive(Args, Clone, Debug)]
pub struct UserStatusSubCommand {
    /// Text note content
    #[arg(short, long)]
    content: String,
    /// Status type (identifier tag)
    #[arg(short, long)]
    status_type: Option<String>,
    /// Pubkey references. Both hex and bech32 encoded keys are supported.
    #[arg(short, long)]
    ptag: Option<String>,
    /// Event references. Both hex and bech32 encoded keys are supported.
    #[arg(short, long)]
    etag: Option<String>,
    /// Reference tag
    #[arg(short, long)]
    rtag: Option<String>,
    /// Seconds till expiration (NIP-40)
    #[arg(long)]
    expiration: Option<u64>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn set_user_status(
    private_key: Option<String>,
    relays: Vec<String>,
    difficulty_target: u8,
    sub_command_args: &UserStatusSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // // Set up tags
    // let mut tags: Vec<Tag> = vec![];

    // // Add identifier tag
    // if let Some(status) = &sub_command_args.status_type {
    //     let status = Tag::Identifier(status.to_string());
    //     tags.push(status);
    // }

    // // Add expiration tag
    // if let Some(expiration) = sub_command_args.expiration {
    //     let timestamp =
    // Timestamp::now().add(Duration::from_secs(expiration));
    //     tags.push(Tag::Expiration(timestamp));
    // }

    // // Add p-tag
    // if let Some(p) = sub_command_args.ptag.clone() {
    //     let pubkey_hex = parse_key(p)?;
    //     let pubkey = XOnlyPublicKey::from_str(&pubkey_hex)?;
    //     tags.push(Tag::PubKey(pubkey, None))
    // }

    // // Add e-tag
    // if let Some(e) = sub_command_args.etag.clone() {
    //     let event_id_hex = parse_key(e)?;
    //     let event_id = EventId::from_hex(event_id_hex)?;
    //     tags.push(Tag::Event(event_id, None, None));
    // }

    // // Add r-tag
    // if let Some(r) = sub_command_args.rtag.clone() {
    //     tags.push(Tag::Reference(r));
    // }

    // // Publish event
    // let event = EventBuilder::new(Kind::Custom(30315),
    // sub_command_args.content.clone(), &tags)     .to_pow_event(&keys,
    // difficulty_target)?; let event_id = client.send_event(event)?;
    // if !sub_command_args.hex {
    //     println!("Published user status with id: {}", event_id.to_bech32()?);
    // } else {
    //     println!("Published user status with id: {}", event_id.to_hex());
    // }

    // Ok(())
}
