use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use serde::{Deserialize, Serialize};

use crate::EmptyCommonInit;

/// Parameters necessary to generate this module's configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyGenParams {
    pub local: EmptyGenParamsLocal,
    pub consensus: EmptyGenParamsConsensus,
}

/// Local parameters for config generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyGenParamsLocal {}

/// Consensus parameters for config generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyGenParamsConsensus {}

impl Default for EmptyGenParams {
    fn default() -> Self {
        Self {
            local: EmptyGenParamsLocal {},
            consensus: EmptyGenParamsConsensus {},
        }
    }
}

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmptyConfig {
    pub local: EmptyConfigLocal,
    pub private: EmptyConfigPrivate,
    pub consensus: EmptyConfigConsensus,
}

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct EmptyClientConfig {}

/// Locally unencrypted config unique to each member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct EmptyConfigLocal {}

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct EmptyConfigConsensus {}

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmptyConfigPrivate;

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    EmptyCommonInit,
    EmptyGenParams,
    EmptyGenParamsLocal,
    EmptyGenParamsConsensus,
    EmptyConfig,
    EmptyConfigLocal,
    EmptyConfigPrivate,
    EmptyConfigConsensus,
    EmptyClientConfig
);
