use bitcoin_hashes::hex::ToHex;
use cln_rpc::primitives::ShortChannelId;
use fedimint_core::Amount;
use fedimint_ln_common::contracts::Preimage;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn scid_to_u64(scid: ShortChannelId) -> u64 {
    let mut scid_num = scid.outnum() as u64;
    scid_num |= (scid.txindex() as u64) << 16;
    scid_num |= (scid.block() as u64) << 40;
    scid_num
}

// TODO: upstream these structs to cln-plugin
// See: https://github.com/ElementsProject/lightning/blob/master/doc/PLUGINS.md#htlc_accepted
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Htlc {
    #[serde(
        deserialize_with = "deserialize_fedimint_amount",
        serialize_with = "serialize_fedimint_amount"
    )]
    pub amount_msat: Amount,
    // TODO: use these to validate we can actually redeem the HTLC in time
    pub cltv_expiry: u32,
    pub cltv_expiry_relative: u32,
    pub payment_hash: bitcoin_hashes::sha256::Hash,
}

/// The core-lightning `htlc_accepted` event's `amount` field has a "msat"
/// suffix
fn deserialize_fedimint_amount<'de, D>(amount: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let amount = String::deserialize(amount)?;
    tracing::info!("deserializing {}", amount);
    Ok(Amount::from_msats(
        amount[0..amount.len() - 4].parse::<u64>().unwrap(),
    ))
}
/// The core-lightning `htlc_accepted` event's `amount` field has a "msat"
/// suffix
fn serialize_fedimint_amount<S>(amount: &Amount, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let string = format!("{}msat", amount.msats);
    s.serialize_str(&string)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Onion {
    #[serde(default)]
    pub short_channel_id: Option<String>,
    #[serde(
        deserialize_with = "deserialize_fedimint_amount",
        serialize_with = "serialize_fedimint_amount"
    )]
    pub forward_msat: Amount,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HtlcAccepted {
    pub htlc: Htlc,
    pub onion: Onion,
}

pub fn htlc_processing_failure() -> serde_json::Value {
    serde_json::json!({
        "result": "fail",
        "failure_message": "1639"
    })
}

pub fn htlc_intercepted(preimage: &Preimage) -> serde_json::Value {
    // FIXME: should be a better way to call `to_hex()`
    serde_json::json!({ "result": "resolve", "payment_key": preimage.0.to_vec().to_hex() })
}
