use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Debug, Clone)]
pub struct VanitySubCommand {
    /// Prefixes
    #[arg(short, long, required = true, action = clap::ArgAction::Append)]
    prefixes: Vec<String>,
    /// Vanity pubkey in hex format
    #[arg(long, default_value_t = false)]
    hex: bool,
}

pub fn vanity(sub_command_args: &VanitySubCommand) -> Result<()> {
    todo!()
    // let num_cores = num_cpus::get();
    // let keys = Keys::vanity(
    //     sub_command_args.prefixes.clone(),
    //     !sub_command_args.hex,
    //     num_cores,
    // )?;

    // if sub_command_args.hex {
    //     println!("Public key (hex): {}", keys.public_key());
    // } else {
    //     println!("Public key: {}", keys.public_key().to_bech32()?);
    // }

    // println!("Private key: {}", keys.secret_key()?.to_bech32()?);

    // Ok(())
}
