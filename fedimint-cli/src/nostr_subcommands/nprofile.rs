use std::str::FromStr;

use clap::{Args, ValueEnum};
use nostr_sdk::prelude::*;

use crate::utils::parse_key;

#[derive(Args, Clone, Debug)]
pub struct NprofileSubCommand {
    /// encode/decode mode
    #[arg(value_enum)]
    mode: Mode,
    /// The bech32 encoded nprofile string to decode. Only used with mode
    /// Decode.
    #[arg(short, long)]
    encoded: Option<String>,
    /// Publickey to encode.
    #[arg(short, long)]
    publickey: Option<String>,
    /// Relays to add to the encoded nprofile.
    #[arg(short, long, action = clap::ArgAction::Append)]
    relays: Vec<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Mode {
    Encode,
    Decode,
}

pub fn nprofile(sub_command_args: &NprofileSubCommand) -> Result<()> {
    match &sub_command_args.mode {
        Mode::Encode => {
            let hex_key = match &sub_command_args.publickey {
                Some(publickey) => parse_key(publickey.clone())?,
                None => {
                    panic!("Publickey was not provided but is required for encoding");
                }
            };
            let pubkey: XOnlyPublicKey = XOnlyPublicKey::from_str(hex_key.as_str())?;
            let profile = Profile::new(pubkey, sub_command_args.relays.clone());
            println!("{}", profile.to_bech32()?);
        }
        Mode::Decode => {
            let profile: Profile = match &sub_command_args.encoded {
                Some(nprofile) => Profile::from_bech32(nprofile)?,
                None => panic!("Nprofile string was not provided but is required for decoding"),
            };
            println!("Publickey: {}", profile.public_key);
            println!("Relays:");
            for relay in profile.relays.iter() {
                println!("{relay}");
            }
        }
    }

    Ok(())
}
