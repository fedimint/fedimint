use crate::mint::SpendableCoin;
use minimint_api::encoding::Decodable;
use minimint_core::modules::mint::tiered::coins::Coins;
use std::error::Error;

pub fn parse_coins(s: &str) -> Coins<SpendableCoin> {
    let bytes = base64::decode(s).unwrap();
    bincode::deserialize(&bytes).unwrap()
}

pub fn serialize_coins(c: &Coins<SpendableCoin>) -> String {
    let bytes = bincode::serialize(&c).unwrap();
    base64::encode(&bytes)
}

pub fn from_hex<D: Decodable>(s: &str) -> Result<D, Box<dyn Error + Send + Sync>> {
    let bytes = hex::decode(s)?;
    Ok(D::consensus_decode(std::io::Cursor::new(bytes))?)
}

pub fn parse_bitcoin_amount(
    s: &str,
) -> Result<bitcoin::Amount, bitcoin::util::amount::ParseAmountError> {
    bitcoin::Amount::from_str_in(s, bitcoin::Denomination::Satoshi)
}
