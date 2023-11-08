use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Clone, Debug)]
pub struct CustomEventCommand {
    /// Event kind
    #[arg(short, long)]
    kind: u64,

    /// Note content
    #[arg(short, long)]
    content: Option<String>,

    /// Arbitrary tags. Specify first the tag key, then separate each string you
    /// want in the array with the character '|'. Example for adding an
    /// a-tag: "a|30001:
    /// b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a:
    /// bookmark|wss://nostr.oxtr.dev"
    ///
    /// This will result in an array that looks like this: ["a",
    /// "30001:b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a:
    /// bookmark", "wss://nostr.oxtr.dev"]
    #[arg(short, long, action = clap::ArgAction::Append)]
    tags: Vec<String>,

    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn create_custom_event(
    _private_key: Option<String>,
    _relays: Vec<String>,
    _difficulty_target: u8,
    _sub_command_args: &CustomEventCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // // Parse kind input
    // let kind = Kind::from(sub_command_args.kind);

    // // Set content
    // let content = match sub_command_args.content.clone() {
    //     Some(content) => content,
    //     None => String::from(""),
    // };

    // // Set up tags
    // let mut tags: Vec<Tag> = vec![];

    // for tag in sub_command_args.tags.clone().iter() {
    //     let parts: Vec<String> = tag.split('|').map(String::from).collect();
    //     let tag_kind = parts.get(0).unwrap().clone();
    //     tags.push(Tag::Generic(TagKind::Custom(tag_kind),
    // parts[1..].to_vec())); }

    // // Initialize event builder
    // let event = EventBuilder::new(kind, content, &tags).to_pow_event(&keys,
    // difficulty_target)?;

    // // Publish event
    // let event_id = client.send_event(event)?;

    // if !sub_command_args.hex {
    //     println!("Published custom event with id: {}",
    // event_id.to_bech32()?); } else {
    //     println!("Published custom event with id: {}", event_id.to_hex());
    // }

    // Ok(())
}
