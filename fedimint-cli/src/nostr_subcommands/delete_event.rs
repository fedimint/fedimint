use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Clone, Debug)]
pub struct DeleteEventSubCommand {
    /// Event id to delete
    #[arg(short, long)]
    event_id: String,
    /// Reason for deleting the events
    #[arg(short, long)]
    reason: Option<String>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn delete(
    _private_key: Option<String>,
    _relays: Vec<String>,
    _difficulty_target: u8,
    _sub_command_args: &DeleteEventSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // let event_id_to_delete_hex =
    // parse_key(sub_command_args.event_id.clone())?; let event_id =
    // EventId::from_hex(event_id_to_delete_hex)?;

    // let event_id = client.delete_event(event_id,
    // sub_command_args.reason.clone())?; if !sub_command_args.hex {
    //     println!("Deleted event with id: {}", event_id.to_bech32()?);
    // } else {
    //     println!("Deleted event with id: {}", event_id.to_hex());
    // }
    // Ok(())
}
