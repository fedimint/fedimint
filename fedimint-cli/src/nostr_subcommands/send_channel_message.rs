use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Debug, Clone)]
pub struct SendChannelMessageSubCommand {
    /// Channel id to send message to
    #[arg(short, long)]
    channel_id: String,
    /// Message content
    #[arg(short, long)]
    message: String,
    // Print keys as hex
    #[arg(long, default_value = "false")]
    hex: bool,
}

pub fn send_channel_message(
    _private_key: Option<String>,
    _relays: Vec<String>,
    _difficulty_target: u8,
    _sub_command_args: &SendChannelMessageSubCommand,
) -> Result<()> {
    todo!()
    // if relays.is_empty() {
    //     panic!("No relays specified, at least one relay is required!")
    // }

    // let keys = handle_keys(private_key, sub_command_args.hex, true)?;
    // let client = create_client(&keys, relays.clone(), difficulty_target)?;

    // let hex_channel_id: String =
    // parse_key(sub_command_args.channel_id.clone())?; let ch_id: ChannelId
    // = ChannelId::from_hex(hex_channel_id)?;

    // let event_id = client.send_channel_msg(
    //     ch_id,
    //     Url::parse(relays[0].as_str())?,
    //     sub_command_args.message.clone(),
    // )?;
    // println!(
    //     "Public channel message sent with id: {}",
    //     event_id.to_bech32()?
    // );

    // Ok(())
}
