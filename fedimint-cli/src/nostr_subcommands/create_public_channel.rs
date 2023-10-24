use clap::Args;
use nostr_sdk::prelude::*;

use crate::utils::{create_client, handle_keys};

#[derive(Args, Clone, Debug)]
pub struct CreatePublicChannelSubCommand {
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

pub fn create_public_channel(
    private_key: Option<String>,
    relays: Vec<String>,
    difficulty_target: u8,
    sub_command_args: &CreatePublicChannelSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // // Process keypair and create a nostr client
    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // // Create metadata
    // let mut metadata = Metadata::new().name(sub_command_args.name.as_str());

    // if let Some(about) = sub_command_args.about.clone() {
    //     metadata = metadata.about(about.as_str());
    // }

    // if let Some(picture) = sub_command_args.picture.clone() {
    //     metadata = metadata.picture(Url::parse(picture.as_str())?);
    // }

    // // Send event
    // let event_id = client.new_channel(metadata)?;

    // // Print results
    // println!("\nCreated new public channel!");
    // println!("Name: {}", sub_command_args.name.as_str());

    // if let Some(about) = sub_command_args.about.clone() {
    //     println!("About: {}", about.as_str());
    // }

    // if let Some(picture) = sub_command_args.picture.clone() {
    //     println!("Picture: {}", picture.as_str());
    // }

    // println!(
    //     "Nchannel id: {}",
    //     ChannelId::from_hex(event_id.to_hex())?.to_bech32()?
    // );
    // println!("Bech32 note id: {}", event_id.to_bech32()?);
    // println!("Hex id: {}", event_id.to_hex());

    // Ok(())
}
