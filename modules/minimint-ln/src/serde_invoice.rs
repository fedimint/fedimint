use serde::{Deserialize, Deserializer};

#[allow(missing_docs)]
pub fn deserialize<'de, D>(deserializer: D) -> Result<lightning_invoice::Invoice, D::Error>
where
    D: Deserializer<'de>,
{
    let bolt11 = String::deserialize(deserializer)?
        .parse::<lightning_invoice::Invoice>()
        .unwrap();

    Ok(bolt11)
}
