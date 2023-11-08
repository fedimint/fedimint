use std::str::FromStr;

use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Clone, Debug)]
pub struct CreateZapRequestCommand {
    /// Optional message
    #[arg(short, long)]
    content: Option<String>,
    /// Relays the zap receipt event should be posted to
    #[arg(short, long, action = clap::ArgAction::Append)]
    relays: Vec<String>,
    /// Amount in millisats
    #[arg(short, long)]
    amount: u64,
    /// lnurl pay url of the recipient
    #[arg(short, long)]
    lnurl: String,
    /// Pubkey references. Both hex and bech32 encoded keys are supported.
    #[arg(short, long, action = clap::ArgAction::Append)]
    ptag: Vec<String>,
    /// Event references. Clients MUST include this if zapping an event rather
    /// than a person.
    #[arg(long, action = clap::ArgAction::Append)]
    etag: Vec<String>,
    // Print keys as hex. Defaults to false.
    #[arg(long, default_value = "false")]
    hex: bool,
    // Write event to a json file. Defaults to true.
    #[arg(short, long, default_value = "true")]
    output_to_file: bool,
}

pub fn create_zap_request(
    _private_key: Option<String>,
    _difficulty_target: u8,
    _sub_command_args: &CreateZapRequestCommand,
) -> Result<()> {
    todo!()
    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;

    // let content = match &sub_command_args.content {
    //     Some(content) => content.as_str(),
    //     None => "",
    // };

    // // Set up tags
    // let mut tags: Vec<Tag> = vec![];

    // // relays tag
    // let cloned_relays = sub_command_args.relays.clone();
    // tags.push(Tag::Relays(parse_relays(cloned_relays)));

    // // amount tag
    // tags.push(Tag::Amount(sub_command_args.amount));

    // // lnurl tag
    // tags.push(Tag::Generic(
    //     TagKind::Custom(String::from("lnurl")),
    //     vec![sub_command_args.lnurl.clone()],
    // ));

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

    // let event = EventBuilder::new(Kind::ZapRequest, content, &tags)
    //     .to_pow_event(&keys, difficulty_target)?;

    // let prettified_json = serde_json::to_string_pretty(&event).unwrap();
    // println!();
    // println!("{}", prettified_json);

    // if sub_command_args.output_to_file {
    //     println!("Writing event json to zap_request.json");
    //     fs::write("zap_request.json", prettified_json)?;
    // }

    // Ok(())
}

fn parse_relays(relays: Vec<String>) -> Vec<UncheckedUrl> {
    relays
        .iter()
        .map(|relay| UncheckedUrl::from_str(relay).unwrap())
        .collect()
}
