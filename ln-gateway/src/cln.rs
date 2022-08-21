use fedimint_api::Amount;
use serde::{Deserialize, Deserializer};

/// The core-lightning `htlc_accepted` event's `amount` field has a "msat" suffix
fn as_fedimint_amount<'de, D>(amount: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let amount = String::deserialize(amount)?;
    Ok(Amount::from_msat(
        amount[0..amount.len() - 4].parse::<u64>().unwrap(),
    ))
}

// TODO: upstream these structs to cln-plugin
#[derive(Clone, Deserialize, Debug)]
pub struct Htlc {
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub amount: Amount,
    pub cltv_expiry: u32,
    pub cltv_expiry_relative: u32,
    pub payment_hash: bitcoin_hashes::sha256::Hash,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Onion {
    pub payload: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub short_channel_id: String,
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub forward_amount: Amount,
    pub outgoing_cltv_value: u32,
    pub shared_secret: bitcoin_hashes::sha256::Hash,
    pub next_onion: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct HtlcAccepted {
    pub htlc: Htlc,
    pub onion: Onion,
}
