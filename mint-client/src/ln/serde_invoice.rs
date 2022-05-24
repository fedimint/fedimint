use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

#[allow(missing_docs)]
pub fn deserialize<'de, D>(deserializer: D) -> Result<lightning_invoice::Invoice, D::Error>
where
    D: Deserializer<'de>,
{
    let bolt11 = String::deserialize(deserializer)?
        .parse::<lightning_invoice::Invoice>()
        .map_err(|e| D::Error::custom(format!("{:?}", e)))?;

    Ok(bolt11)
}

pub fn serialize<S>(invoice: &lightning_invoice::Invoice, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(invoice.to_string().as_str())
}
