use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Debug, Clone)]
pub struct SetChannelMetadataSubCommand {
    /// Channel ID
    #[arg(short, long)]
    channel_id: String,
    /// Recommended relay
    #[arg(short, long)]
    recommended_relay: Option<String>,
    /// Channel name
    #[arg(short, long)]
    name: String,
    /// Channel about
    #[arg(short, long)]
    about: Option<String>,
    /// Channel picture
    #[arg(short, long)]
    picture: Option<String>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn set_channel_metadata(
    _private_key: Option<String>,
    _relays: Vec<String>,
    _difficulty_target: u8,
    _sub_command_args: &SetChannelMetadataSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // // Process keypair and create a nostr client
    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays.clone(), difficulty_target)?;

    // // Parse the channel id which can both be hex or bech32 encoded
    // let hex_channel_id: String =
    // parse_key(sub_command_args.channel_id.clone())?;

    // // Build ChannelId object which is required in set_channel_metadata
    // function let sha256 =
    // bitcoin::hashes::sha256::Hash::from_str(hex_channel_id.as_str())?;
    // let channel_id = ChannelId::new(sha256, relays);
    // // Build relay URL
    // let relay_url: Option<Url> = match &sub_command_args.recommended_relay {
    //     Some(url) => Some(Url::parse(url.as_str())?),
    //     None => None,
    // };

    // // Build updated metadata
    // let mut metadata = Metadata::new().name(sub_command_args.name.as_str());
    // if let Some(about) = sub_command_args.about.clone() {
    //     metadata = metadata.about(about.as_str());
    // }
    // if let Some(picture) = sub_command_args.picture.clone() {
    //     metadata = metadata.picture(Url::parse(picture.as_str())?);
    // }

    // // Send event
    // let event_id = client.set_channel_metadata(channel_id, relay_url,
    // metadata)?;

    // // Print results
    // println!("\nSet new metadata for channel!");
    // println!("Channel id: {}", sub_command_args.channel_id.as_str());
    // println!("Name: {}", sub_command_args.name.as_str());

    // if let Some(about) = sub_command_args.about.clone() {
    //     println!("About: {}", about.as_str());
    // }

    // if let Some(picture) = sub_command_args.picture.clone() {
    //     println!("Picture: {}", picture.as_str());
    // }

    // println!("Bech32 event id: {}", event_id.to_bech32()?);
    // println!("Hex event id: {}", event_id.to_hex());

    // Ok(())
}
