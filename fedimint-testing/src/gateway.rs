use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_lightning::ILnRpcClient;
use ln_gateway::config::LightningBuilder;

use crate::ln::FakeLightningTest;

pub const DEFAULT_GATEWAY_PASSWORD: &str = "thereisnosecondbest";

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum LightningNodeType {
    Lnd,
    Ldk,
}

impl Display for LightningNodeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            LightningNodeType::Lnd => write!(f, "lnd"),
            LightningNodeType::Ldk => write!(f, "ldk"),
        }
    }
}

impl FromStr for LightningNodeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
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
    async fn build(&self, runtime: Arc<tokio::runtime::Runtime>) -> Box<dyn ILnRpcClient> {
        // Runtimes must be dropped in a blocking context. Removing this line can lead
        // to panics.
        fedimint_core::runtime::block_in_place(|| drop(runtime));
        Box::new(FakeLightningTest::new())
    }
}
