use std::num::ParseIntError;
use std::str::FromStr;

use bitcoin::{secp256k1, Network};
use bitcoin_hashes::hex::FromHex;
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_core::api::DynGlobalApi;
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{ParseAmountError, PeerId, TieredMulti};
use lightning_invoice::Currency;

use crate::mint::SpendableNote;

pub fn parse_ecash(s: &str) -> anyhow::Result<TieredMulti<SpendableNote>> {
    let bytes = base64::decode(s)?;
    Ok(Decodable::consensus_decode(
        &mut std::io::Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )?)
}

pub fn serialize_ecash(c: &TieredMulti<SpendableNote>) -> String {
    let mut bytes = Vec::new();
    Encodable::consensus_encode(c, &mut bytes).expect("encodes correctly");
    base64::encode(&bytes)
}

pub fn from_hex<D: Decodable>(s: &str) -> Result<D, anyhow::Error> {
    let bytes = Vec::from_hex(s)?;
    Ok(D::consensus_decode(
        &mut std::io::Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )?)
}

pub fn parse_bitcoin_amount(
    s: &str,
) -> Result<bitcoin::Amount, bitcoin::util::amount::ParseAmountError> {
    if let Some(i) = s.find(char::is_alphabetic) {
        let (amt, denom) = s.split_at(i);
        bitcoin::Amount::from_str_in(amt, denom.parse()?)
    } else {
        //default to satoshi
        bitcoin::Amount::from_str_in(s, bitcoin::Denomination::Satoshi)
    }
}

pub fn parse_fedimint_amount(s: &str) -> Result<fedimint_core::Amount, ParseAmountError> {
    if let Some(i) = s.find(char::is_alphabetic) {
        let (amt, denom) = s.split_at(i);
        fedimint_core::Amount::from_str_in(amt, denom.parse()?)
    } else {
        //default to millisatoshi
        fedimint_core::Amount::from_str_in(s, bitcoin::Denomination::MilliSatoshi)
    }
}

pub fn parse_gateway_id(s: &str) -> Result<secp256k1::PublicKey, secp256k1::Error> {
    secp256k1::PublicKey::from_str(s)
}

pub fn parse_peer_id(s: &str) -> Result<PeerId, ParseIntError> {
    Ok(PeerId::from(s.parse::<u16>()?))
}

#[derive(Debug)]
pub struct ClientContext {
    pub decoders: ModuleDecoderRegistry,
    pub module_gens: ClientModuleGenRegistry,
    pub db: Database,
    pub api: DynGlobalApi,
    pub secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
}

pub fn network_to_currency(network: Network) -> Currency {
    match network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Regtest => Currency::Regtest,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Signet => Currency::Signet,
    }
}

#[test]
fn sanity_check_parse_fedimint_amount() {
    assert_eq!(
        parse_fedimint_amount("34").unwrap(),
        fedimint_core::Amount { msats: 34 }
    );
    assert_eq!(
        parse_fedimint_amount("34msat").unwrap(),
        fedimint_core::Amount { msats: 34 }
    );
    assert_eq!(
        parse_fedimint_amount("34sat").unwrap(),
        fedimint_core::Amount { msats: 34 * 1000 }
    );
    assert_eq!(
        parse_fedimint_amount("34satoshi").unwrap(),
        fedimint_core::Amount { msats: 34 * 1000 }
    );
}
