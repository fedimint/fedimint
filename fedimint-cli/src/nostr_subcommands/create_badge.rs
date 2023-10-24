use clap::Args;
use nostr_sdk::prelude::*;

use crate::utils::{create_client, handle_keys};

#[derive(Args, Debug, Clone)]
pub struct CreateBadgeSubCommand {
    /// Unique identifier for the badge
    #[arg(short, long)]
    id: String,
    ///
    #[arg(short, long)]
    name: Option<String>,
    ///
    #[arg(short, long)]
    description: Option<String>,
    ///
    #[arg(long)]
    image_url: Option<String>,
    ///
    #[arg(long)]
    image_size_width: Option<u64>,
    ///
    #[arg(long)]
    image_size_height: Option<u64>,
    ///
    #[arg(short, long)]
    thumb_url: Option<String>,
    ///
    #[arg(long)]
    thumb_size_width: Option<u64>,
    ///
    #[arg(long)]
    thumb_size_height: Option<u64>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn create_badge(
    private_key: Option<String>,
    relays: Vec<String>,
    difficulty_target: u8,
    sub_command_args: &CreateBadgeSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // let image_size = match (
    //     sub_command_args.image_size_height,
    //     sub_command_args.image_size_width,
    // ) { (Some(height), Some(width)) => Some(ImageDimensions { height, width
    //   }), _ => None,
    // };

    // let thumbnails = if let Some(thumb_url) =
    // sub_command_args.thumb_url.clone() {     let thumb_size = match (
    //         sub_command_args.thumb_size_height,
    //         sub_command_args.thumb_size_width,
    //     ) { (Some(width), Some(height)) => Some((width, height)), _ => None,
    //     };

    //     let url = UncheckedUrl::from(thumb_url);

    //     if let Some((width, height)) = thumb_size {
    //         Some(vec![(url, Some(ImageDimensions { width, height }))])
    //     } else {
    //         Some(vec![(url, None)])
    //     }
    // } else {
    //     None
    // };

    // let image_url: Option<UncheckedUrl> =
    //     sub_command_args.image_url.clone().map(UncheckedUrl::from);

    // let event = EventBuilder::define_badge(
    //     sub_command_args.id.clone(),
    //     sub_command_args.name.clone(),
    //     sub_command_args.description.clone(),
    //     image_url,
    //     image_size,
    //     thumbnails,
    // )
    // .to_pow_event(&keys, difficulty_target)?;

    // // Publish event
    // let event_id = client.send_event(event)?;
    // if !sub_command_args.hex {
    //     println!(
    //         "Published badge definition with id: {}",
    //         event_id.to_bech32()?
    //     );
    // } else {
    //     println!("Published badge definition with id: {}",
    // event_id.to_hex()); }

    // Ok(())
}
