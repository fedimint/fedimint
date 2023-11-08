use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Clone, Debug)]
pub struct HidePublicChannelMessageSubCommand {
    /// Reason for hiding
    #[arg(short, long)]
    reason: Option<String>,
    /// Event to hide
    #[arg(short, long)]
    event_id: String,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn hide_public_channel_message(
    _private_key: Option<String>,
    _relays: Vec<String>,
    _difficulty_target: u8,
    _sub_command_args: &HidePublicChannelMessageSubCommand,
) -> Result<()> {
    todo!()
    //     if relays.is_empty() {
    //         panic!("No relays specified, at least one relay is required!")
    //     }

    //     let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    //     let client = create_client(&keys, relays, difficulty_target)?;

    //     // Set up eventId
    //     let hex_event_id = parse_key(sub_command_args.event_id.clone())?;
    //     let event_id_to_hide = EventId::from_hex(hex_event_id)?;

    //     client.hide_channel_msg(event_id_to_hide,
    // sub_command_args.reason.clone())?;     println!("Channel message with
    // id {event_id_to_hide} successfully hidden");

    //     Ok(())
}
