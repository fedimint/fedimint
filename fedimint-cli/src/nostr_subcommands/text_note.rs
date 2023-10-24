use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;

use clap::Args;
use nostr_sdk::prelude::*;

use crate::utils::{create_client, handle_keys, parse_key};

#[derive(Args, Clone, Debug)]
pub struct TextNoteSubCommand {
    /// Text note content
    #[arg(short, long)]
    content: String,
    /// Subject tag (NIP-14)
    #[arg(short, long)]
    subject: Option<String>,
    /// Pubkey references. Both hex and bech32 encoded keys are supported.
    #[arg(long, action = clap::ArgAction::Append)]
    ptag: Vec<String>,
    /// Event references
    #[arg(long, action = clap::ArgAction::Append)]
    etag: Vec<String>,
    /// Seconds till expiration (NIP-40)
    #[arg(long)]
    expiration: Option<u64>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn broadcast_textnote(
    private_key: Option<String>,
    relays: Vec<String>,
    difficulty_target: u8,
    sub_command_args: &TextNoteSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // // Set up tags
    // let mut tags: Vec<Tag> = vec![];

    // // Subject tag (NIP-14)
    // if let Some(subject) = &sub_command_args.subject {
    //     let subject_tag = Tag::Subject(subject.clone());
    //     tags.push(subject_tag);
    // }

    // // Any p-tag
    // for ptag in sub_command_args.ptag.iter() {
    //     // Parse pubkey to ensure we're sending hex keys
    //     let pubkey_hex = parse_key(ptag.clone())?;
    //     let pubkey = XOnlyPublicKey::from_str(&pubkey_hex)?;
    //     tags.push(Tag::PubKey(pubkey, None));
    // }
    // // Any e-tag
    // for etag in sub_command_args.etag.iter() {
    //     let event_id = EventId::from_hex(etag)?;
    //     tags.push(Tag::Event(event_id, None, None));
    // }
    // // Set expiration tag
    // if let Some(expiration) = sub_command_args.expiration {
    //     let timestamp =
    // Timestamp::now().add(Duration::from_secs(expiration));
    //     tags.push(Tag::Expiration(timestamp));
    // }

    // // Publish event
    // let event_id = client.publish_text_note(sub_command_args.content.clone(),
    // &tags)?; if !sub_command_args.hex {
    //     println!("Published text note with id: {}", event_id.to_bech32()?);
    // } else {
    //     println!("Published text note with id: {}", event_id.to_hex());
    // }

    // Ok(())
}
