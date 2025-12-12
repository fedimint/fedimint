use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use serde::{Deserialize, Serialize};

use crate::EmptyCommonInit;

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmptyConfig {
    pub private: EmptyConfigPrivate,
    pub consensus: EmptyConfigConsensus,
}

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct EmptyClientConfig {}

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct EmptyConfigConsensus {}

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmptyConfigPrivate;

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    EmptyCommonInit,
    EmptyConfig,
    EmptyConfigPrivate,
    EmptyConfigConsensus,
    EmptyClientConfig
);
