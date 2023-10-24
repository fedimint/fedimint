use clap::Args;
use nostr_sdk::nostr::nips::nip05;
use nostr_sdk::prelude::*;

use crate::utils::{create_client, handle_keys};

#[derive(Args, Debug, Clone)]
pub struct UpdateMetadataSubCommand {
    /// Profile name
    #[arg(short, long)]
    name: Option<String>,
    /// About
    #[arg(short, long)]
    about: Option<String>,
    /// Picture URL
    #[arg(short, long)]
    picture: Option<String>,
    #[arg(long)]
    nip05: Option<String>,
    #[arg(long)]
    lud06: Option<String>,
    #[arg(long)]
    lud16: Option<String>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn update_metadata(
    private_key: Option<String>,
    relays: Vec<String>,
    difficulty_target: u8,
    sub_command_args: &UpdateMetadataSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // let mut metadata = Metadata::new();

    // // Name
    // if let Some(name) = &sub_command_args.name {
    //     metadata = metadata.name(name);
    // }

    // // About
    // if let Some(about) = &sub_command_args.about {
    //     metadata = metadata.about(about);
    // }

    // // Picture URL
    // if let Some(picture_url) = &sub_command_args.picture {
    //     let url = Url::parse(picture_url)?;
    //     metadata = metadata.picture(url);
    // };

    // // NIP-05 identifier
    // if let Some(nip05_identifier) = &sub_command_args.nip05 {
    //     // Check if the nip05 is valid
    //     // nip05::verify_blocking(keys.public_key(),
    // nip05_identifier.as_str(), None)?;     metadata =
    // metadata.nip05(nip05_identifier); }

    // // LUD-06 string
    // if let Some(lud06) = &sub_command_args.lud06 {
    //     metadata = metadata.lud06(lud06);
    // }

    // // LUD-16 string
    // if let Some(lud16) = &sub_command_args.lud16 {
    //     metadata = metadata.lud16(lud16);
    // }

    // let event_id = client.set_metadata(metadata)?;
    // println!("Metadata updated ({})", event_id.to_bech32()?);

    // Ok(())
}
