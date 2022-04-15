use serde::de::Error;
use serde::{Deserialize, Deserializer};

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
