use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug)]
pub enum Connector {
    Tcp,
    Tor,
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
        match s {
            "Tcp" => Ok(Connector::Tcp),
            "Tor" => Ok(Connector::Tor),
            _ => Err("invalid connector!"),
        }
    }
}
