use std::fmt::{self};
use std::str::FromStr;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum LightningNodeType {
    Lnd,
    Ldk,
    /// Gateway running without a Lightning node attached.
    None,
}

impl fmt::Display for LightningNodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            LightningNodeType::Lnd => write!(f, "lnd"),
            LightningNodeType::Ldk => write!(f, "ldk"),
            LightningNodeType::None => write!(f, "none"),
        }
    }
}

impl FromStr for LightningNodeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "lnd" => Ok(LightningNodeType::Lnd),
            "ldk" => Ok(LightningNodeType::Ldk),
            "none" => Ok(LightningNodeType::None),
            _ => Err(format!("Invalid value for LightningNodeType: {s}")),
        }
    }
}
