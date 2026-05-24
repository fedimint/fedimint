use fedimint_core::{plugin_types_trait_impl_config};
use fedimint_core::encoding::{Encodable,Decodable};
use fedimint_core::core::{ModuleKind};

use std::fmt;
use serde::{Deserialize, Serialize};
use crate::EscrowCommonInit;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowConfig {
    pub private: EscrowConfigPrivate,
    pub consensus: EscrowConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowConfigPrivate;

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct EscrowConfigConsensus;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct EscrowClientConfig;

plugin_types_trait_impl_config!(
    EscrowCommonInit,
    EscrowConfig,
    EscrowConfigPrivate,
    EscrowConfigConsensus,
    EscrowClientConfig
);


impl std::fmt::Display for EscrowClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EscrowClientConfig")
    }
}