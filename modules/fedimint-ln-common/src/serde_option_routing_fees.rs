use lightning_invoice::RoutingFees;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serializer};

#[allow(missing_docs)]
pub fn serialize<S>(fees: &Option<RoutingFees>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(fees) = fees {
        let mut state = serializer.serialize_struct("RoutingFees", 2)?;
        state.serialize_field("base_msat", &fees.base_msat)?;
        state.serialize_field("proportional_millionths", &fees.proportional_millionths)?;
        state.end()
    } else {
        let state = serializer.serialize_struct("RoutingFees", 0)?;
        state.end()
    }
}

#[allow(missing_docs)]
pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<RoutingFees>, D::Error>
where
    D: Deserializer<'de>,
{
    let fees = serde_json::Value::deserialize(deserializer)?;
    // While we deserialize fields as u64, RoutingFees expects u32 for the fields
    let base_msat = fees["base_msat"].as_u64();

    if let Some(base_msat) = base_msat
        && let Some(proportional_millionths) = fees["proportional_millionths"].as_u64()
    {
        let base_msat: u32 = base_msat
            .try_into()
            .map_err(|_| serde::de::Error::custom("base_msat is greater than u32::MAX"))?;
        let proportional_millionths: u32 = proportional_millionths.try_into().map_err(|_| {
            serde::de::Error::custom("proportional_millionths is greater than u32::MAX")
        })?;
        return Ok(Some(RoutingFees {
            base_msat,
            proportional_millionths,
        }));
    }

    Ok(None)
}
