use std::fmt::{Display, Formatter};
use std::str::FromStr;

use async_trait::async_trait;
use ln_gateway::lightning::{ILnRpcClient, LightningBuilder};

use crate::ln::FakeLightningTest;

pub const DEFAULT_GATEWAY_PASSWORD: &str = "thereisnosecondbest";

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LightningNodeType {
    Cln,
    Lnd,
    Ldk,
}

impl Display for LightningNodeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            LightningNodeType::Cln => write!(f, "cln"),
            LightningNodeType::Lnd => write!(f, "lnd"),
            LightningNodeType::Ldk => write!(f, "ldk"),
        }
    }
}

impl FromStr for LightningNodeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cln" => Ok(LightningNodeType::Cln),
            "lnd" => Ok(LightningNodeType::Lnd),
            "ldk" => Ok(LightningNodeType::Ldk),
            _ => Err(format!("Invalid value for LightningNodeType: {s}")),
        }
    }
}

#[derive(Clone)]
pub struct FakeLightningBuilder;

#[async_trait]
impl LightningBuilder for FakeLightningBuilder {
    async fn build(&self) -> Box<dyn ILnRpcClient> {
        Box::new(FakeLightningTest::new())
    }
}
