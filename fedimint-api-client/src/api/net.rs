use std::fmt;
use std::str::FromStr;

use fedimint_core::encoding::{Decodable, Encodable};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub enum Connector {
    Tcp,
    #[cfg(feature = "tor")]
    Tor,
}

impl Connector {
    #[cfg(feature = "tor")]
    pub fn tor() -> Connector {
        Connector::Tor
    }
}

impl Default for Connector {
    fn default() -> Self {
        Self::Tcp
    }
}

impl fmt::Display for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for Connector {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Connector::Tcp),
            #[cfg(feature = "tor")]
            "tor" => Ok(Connector::Tor),
            _ => Err("invalid connector!"),
        }
    }
}
