use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Debug, Clone)]
pub struct SendDirectMessageSubCommand {
    /// Receiver public key. Both hex and bech32 encoded keys are supported.
    #[arg(short, long)]
    pub receiver: String,
    /// Message to send
    #[arg(short, long)]
    pub message: String,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn send(
    _private_key: Option<String>,
    _relays: Vec<String>,
    _difficulty_target: u8,
    _sub_command_args: &SendDirectMessageSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays, difficulty_target);

    // let hex_pubkey = parse_key(sub_command_args.receiver.clone())?;
    // let receiver = XOnlyPublicKey::from_str(&hex_pubkey)?;

    // let event_id = client?.send_direct_msg(receiver,
    // sub_command_args.message.clone(), None)?; if !sub_command_args.hex {
    //     println!(
    //         "Message sent to {}, event id: {}",
    //         receiver.to_bech32()?,
    //         event_id.to_bech32()?
    //     );
    // } else {
    //     println!(
    //         "Message sent to {}, event id: {}",
    //         receiver,
    //         event_id.to_hex()
    //     );
    // }
    // Ok(())
}
