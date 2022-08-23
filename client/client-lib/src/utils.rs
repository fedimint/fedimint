use crate::api::FederationApi;
use crate::mint::SpendableCoin;
use bitcoin::Network;
use fedimint_api::db::Database;
use fedimint_api::encoding::Decodable;
use fedimint_api::ParseAmountError;
use fedimint_core::modules::mint::tiered::coins::Coins;
use lightning_invoice::Currency;

pub fn parse_coins(s: &str) -> Coins<SpendableCoin> {
    let bytes = base64::decode(s).unwrap();
    bincode::deserialize(&bytes).unwrap()
}

pub fn serialize_coins(c: &Coins<SpendableCoin>) -> String {
    let bytes = bincode::serialize(&c).unwrap();
    base64::encode(&bytes)
}

pub fn from_hex<D: Decodable>(s: &str) -> Result<D, anyhow::Error> {
    let bytes = hex::decode(s)?;
    Ok(D::consensus_decode(std::io::Cursor::new(bytes))?)
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

pub fn parse_fedimint_amount(s: &str) -> Result<fedimint_api::Amount, ParseAmountError> {
    if let Some(i) = s.find(char::is_alphabetic) {
        let (amt, denom) = s.split_at(i);
        fedimint_api::Amount::from_str_in(amt, denom.parse()?)
    } else {
        //default to satoshi
        fedimint_api::Amount::from_str_in(s, bitcoin::Denomination::Satoshi)
    }
}
pub struct OwnedClientContext {
    pub db: Box<dyn Database>,
    pub api: Box<dyn FederationApi>,
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
