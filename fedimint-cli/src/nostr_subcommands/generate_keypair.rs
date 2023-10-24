use clap::Args;
use nostr_sdk::prelude::*;

#[derive(Args, Debug, Clone)]
pub struct GenerateKeypairSubCommand {
    /// Print keys in hex. Defaults to printing bech32 encoded keys.
    #[arg(short, long, default_value = "false")]
    print_hex: bool,
}

pub fn get_new_keypair(sub_command_args: &GenerateKeypairSubCommand) -> Result<()> {
    todo!()
    // let keys = Keys::generate();
    // if sub_command_args.print_hex {
    //     println!("Private key: {}", keys.secret_key()?.display_secret());
    //     println!("Public key: {}", keys.public_key())
    // } else {
    //     println!("Private key: {}", keys.secret_key()?.to_bech32()?);
    //     println!("Public key: {}", keys.public_key().to_bech32()?);
    // }
    // Ok(())
}
