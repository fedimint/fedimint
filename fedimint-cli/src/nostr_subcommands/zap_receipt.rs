use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Clone, Debug)]
pub struct SendZapSubCommand {
    /// Bolt 11 invoice string
    #[arg(short, long)]
    bolt11: String,
    /// The path to a json document containing the zap request event json
    #[arg(short, long)]
    zap_request_json_path: String,
    /// Payment hash of the bolt11 invoice
    #[arg(short, long)]
    preimage: Option<String>,
    /// Pubkey references. Both hex and bech32 encoded keys are supported.
    #[arg(long, action = clap::ArgAction::Append)]
    ptag: Vec<String>,
    /// Event references
    #[arg(long, action = clap::ArgAction::Append)]
    etag: Vec<String>,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn send_zap_receipt(
    _private_key: Option<String>,
    _relays: Vec<String>,
    _difficulty_target: u8,
    _sub_command_args: &SendZapSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target)?;

    // // Read in json from specified file
    // let event_json: String =
    // fs::read_to_string(sub_command_args.zap_request_json_path.clone())?;
    // // Create Event from json
    // let zap_request_event = Event::from_json(event_json)?;

    // let event: Event = EventBuilder::new_zap_receipt(
    //     sub_command_args.bolt11.clone(),
    //     sub_command_args.preimage.clone(),
    //     zap_request_event,
    // )
    // .to_pow_event(&keys, difficulty_target)?;

    // // Publish event
    // let event_id = client.send_event(event)?;
    // if !sub_command_args.hex {
    //     println!("Published zap receipt with id: {}", event_id.to_bech32()?);
    // } else {
    //     println!("Published zap receipt with id: {}", event_id.to_hex());
    // }

    // Ok(())
}
