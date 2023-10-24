use std::str::FromStr;

use clap::Args;
use nostr_sdk::prelude::*;

use crate::utils::{parse_key, Prefix};

#[derive(Args, Debug, Clone)]
pub struct ConvertKeySubCommand {
    /// Pubkey in bech32 or hex format
    #[arg(short, long)]
    key: String,
    /// Bech32 prefix. Only used if you're converting from hex to bech32 encoded
    /// keys.
    #[arg(short, long)]
    prefix: Option<Prefix>,
    /// Set to true if you're converting from bech32 to hex
    #[arg(short, long, default_value = "false")]
    to_hex: bool,
}

pub fn convert_key(sub_command_args: &ConvertKeySubCommand) -> Result<()> {
    let unknown_key = &sub_command_args.key.clone();
    let hex_key = parse_key(unknown_key.to_string())?;

    if sub_command_args.to_hex {
        println!("{hex_key}");
    } else {
        let encoded_key: String = match sub_command_args
            .prefix
            .as_ref()
            .expect("Prefix parameter is missing")
        {
            Prefix::Npub => XOnlyPublicKey::from_str(hex_key.as_str())?.to_bech32()?,
            Prefix::Nsec => SecretKey::from_str(hex_key.as_str())?.to_bech32()?,
            Prefix::Note => EventId::from_hex(hex_key)?.to_bech32()?,
            Prefix::Nchannel => ChannelId::from_hex(hex_key)?.to_bech32()?,
        };
        println!("{encoded_key}");
    }

    Ok(())
}
