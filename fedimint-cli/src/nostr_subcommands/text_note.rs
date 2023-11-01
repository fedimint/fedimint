use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;

use clap::Args;
use fedimint_client::Client;
use nostr_sdk::secp256k1::XOnlyPublicKey;
use nostr_sdk::{Event, EventId, Tag, Timestamp, ToBech32};
use resolvr_client::ResolvrClientExt;

use crate::utils::parse_key;

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

pub async fn broadcast_textnote(
    client: Client,
    sub_command_args: &TextNoteSubCommand,
) -> anyhow::Result<EventId> {
    // Set up tags
    let mut tags: Vec<Tag> = vec![];

    // Subject tag (NIP-14)
    if let Some(subject) = &sub_command_args.subject {
        let subject_tag = Tag::Subject(subject.clone());
        tags.push(subject_tag);
    }

    // Any p-tag
    for ptag in sub_command_args.ptag.iter() {
        // Parse pubkey to ensure we're sending hex keys
        let pubkey_hex = parse_key(ptag.clone()).unwrap();
        let pubkey = XOnlyPublicKey::from_str(&pubkey_hex)?;
        tags.push(Tag::PubKey(pubkey, None));
    }
    // Any e-tag
    for etag in sub_command_args.etag.iter() {
        let event_id = EventId::from_hex(etag)?;
        tags.push(Tag::Event(event_id, None, None));
    }
    // Set expiration tag
    if let Some(expiration) = sub_command_args.expiration {
        let timestamp = Timestamp::now().add(Duration::from_secs(expiration));
        tags.push(Tag::Expiration(timestamp));
    }

    // sign nostrmint with front

    let pubkey = client.get_npub().await?;
    let unsigned_event =
        nostr_sdk::EventBuilder::new_text_note(sub_command_args.clone().content, &tags)
            .to_unsigned_event(pubkey);
    client.request_sign_event(unsigned_event.clone()).await?;

    // then
    // get signed event back

    println!(
        "Published text note with id: {}",
        unsigned_event.id.to_bech32()?
    );

    Ok(unsigned_event.id)
}
