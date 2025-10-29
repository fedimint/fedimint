use std::fmt;
use std::str::FromStr;

use fedimint_core::encoding::{Decodable, Encodable};
use serde::{Deserialize, Serialize};

/// TODO: rename, or even remove?
#[derive(Clone, Copy, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub enum ConnectorType {
    Tcp,
    #[cfg(feature = "tor")]
    Tor,
}

impl ConnectorType {
    #[cfg(feature = "tor")]
    pub fn tor() -> ConnectorType {
        ConnectorType::Tor
    }
}

impl Default for ConnectorType {
    fn default() -> Self {
        Self::Tcp
    }
}

impl fmt::Display for ConnectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for ConnectorType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(ConnectorType::Tcp),
            #[cfg(feature = "tor")]
            "tor" => Ok(ConnectorType::Tor),
            _ => Err("invalid connector!"),
        }
    }
}
