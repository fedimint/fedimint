// TODO: Upstream serde serialization for
// lightning_invoice::RoutingFees
// See https://github.com/lightningdevkit/rust-lightning/blob/b8ed4d2608e32128dd5a1dee92911638a4301138/lightning/src/routing/gossip.rs#L1057-L1065
use lightning_invoice::RoutingFees;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serializer};

#[allow(missing_docs)]
pub fn serialize<S>(fees: &RoutingFees, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("RoutingFees", 2)?;
    state.serialize_field("base_msat", &fees.base_msat)?;
    state.serialize_field("proportional_millionths", &fees.proportional_millionths)?;
    state.end()
}

#[allow(missing_docs)]
pub fn deserialize<'de, D>(deserializer: D) -> Result<RoutingFees, D::Error>
where
    D: Deserializer<'de>,
{
    let fees = serde_json::Value::deserialize(deserializer)?;
    // While we deserialize fields as u64, RoutingFees expects u32 for the fields
    let base_msat = fees["base_msat"]
        .as_u64()
        .ok_or_else(|| serde::de::Error::custom("base_msat is not a u64"))?;
    let proportional_millionths = fees["proportional_millionths"]
        .as_u64()
        .ok_or_else(|| serde::de::Error::custom("proportional_millionths is not a u64"))?;

    Ok(RoutingFees {
        base_msat: base_msat
            .try_into()
            .map_err(|_| serde::de::Error::custom("base_msat is greater than u32::MAX"))?,
        proportional_millionths: proportional_millionths.try_into().map_err(|_| {
            serde::de::Error::custom("proportional_millionths is greater than u32::MAX")
        })?,
    })
}
