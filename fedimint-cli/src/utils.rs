use std::num::ParseIntError;

use bitcoin_hashes::hex::FromHex;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::PeerId;
use nostr_sdk::prelude::*;
use nostr_sdk::Client;

pub fn from_hex<D: Decodable>(s: &str) -> Result<D, anyhow::Error> {
    let bytes = Vec::from_hex(s)?;
    Ok(D::consensus_decode(
        &mut std::io::Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )?)
}

pub fn parse_peer_id(s: &str) -> Result<PeerId, ParseIntError> {
    Ok(PeerId::from(s.parse::<u16>()?))
}

pub fn handle_keys(private_key: Option<String>, hex: bool, print_keys: bool) -> Result<Keys> {
    // Parse and validate private key
    let keys = match private_key {
        Some(pk) => {
            // create a new identity using the provided private key
            Keys::from_sk_str(pk.as_str())?
        }
        None => {
            // create a new identity with a new keypair
            if print_keys {
                println!("No private key provided, creating new identity");
            }
            Keys::generate()
        }
    };

    if print_keys {
        if !hex {
            println!("Private key: {}", keys.secret_key()?.to_bech32()?);
            println!("Public key: {}", keys.public_key().to_bech32()?);
        } else {
            println!("Private key: {}", keys.secret_key()?.display_secret());
            println!("Public key: {}", keys.public_key());
        }
    }

    Ok(keys)
}

// Creates the websocket client that is used for communicating with relays
pub fn create_client(_keys: &Keys, _relays: Vec<String>, _difficulty: u8) -> Result<Client> {
    todo!()
    // let opts = Options::new().wait_for_send(true).difficulty(difficulty);
    // let client = Client::with_opts(keys, opts);
    // let relays = relays.iter().map(|url| (url.clone(), None)).collect();
    // client.add_relays(relays)?;
    // client.connect();
    // Ok(client)
}

// Accepts both hex and bech32 keys and returns the hex encoded key
pub fn parse_key(key: String) -> Result<String> {
    // Check if the key is a bech32 encoded key
    let parsed_key = if key.starts_with("npub") {
        XOnlyPublicKey::from_bech32(key)?.to_string()
    } else if key.starts_with("nsec") {
        SecretKey::from_bech32(key)?.display_secret().to_string()
    } else if key.starts_with("note") {
        EventId::from_bech32(key)?.to_hex()
    } else if key.starts_with("nchannel") {
        ChannelId::from_bech32(key)?.to_hex()
    } else {
        // If the key is not bech32 encoded, return it as is
        key
    };
    Ok(parsed_key)
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Prefix {
    Npub,
    Nsec,
    Note,
    Nchannel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_hex_input() {
        let hex_key =
            String::from("f4deaad98b61fa24d86ef315f1d5d57c1a6a533e1e87e777e5d0b48dcd332cdb");
        let result = parse_key(hex_key.clone());

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), hex_key);
    }

    #[test]
    fn test_parse_key_bech32_note_input() {
        let bech32_note_id =
            String::from("note1h445ule4je70k7kvddate8kpsh2fd6n77esevww5hmgda2qwssjsw957wk");
        let result = parse_key(bech32_note_id);

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            String::from("bd6b4e7f35967cfb7acc6b7abc9ec185d496ea7ef6619639d4bed0dea80e8425")
        );
    }

    #[test]
    fn test_parse_bech32_public_key_input() {
        let bech32_encoded_key =
            String::from("npub1ktt8phjnkfmfrsxrgqpztdjuxk3x6psf80xyray0l3c7pyrln49qhkyhz0");
        let result = parse_key(bech32_encoded_key);

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            String::from("b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a")
        );
    }

    #[test]
    fn test_parse_bech32_private_key() {
        let bech32_encoded_key =
            String::from("nsec1hdeqm0y8vgzuucqv4840h7rlpy4qfu928ulxh3dzj6s2nqupdtzqagtew3");
        let result = parse_key(bech32_encoded_key);

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            String::from("bb720dbc876205ce600ca9eafbf87f092a04f0aa3f3e6bc5a296a0a983816ac4")
        );
    }
}
