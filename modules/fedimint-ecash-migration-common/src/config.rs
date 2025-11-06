use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use serde::{Deserialize, Serialize};

use crate::EcashMigrationCommonInit;

/// Parameters necessary to generate this module's configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcashMigrationGenParams {
    pub local: EcashMigrationGenParamsLocal,
    pub consensus: EcashMigrationGenParamsConsensus,
}

/// Local parameters for config generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcashMigrationGenParamsLocal {}

/// Consensus parameters for config generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcashMigrationGenParamsConsensus {}

impl Default for EcashMigrationGenParams {
    fn default() -> Self {
        Self {
            local: EcashMigrationGenParamsLocal {},
            consensus: EcashMigrationGenParamsConsensus {},
        }
    }
}

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcashMigrationConfig {
    pub private: EcashMigrationConfigPrivate,
    pub consensus: EcashMigrationConfigConsensus,
}

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct EcashMigrationClientConfig {}

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct EcashMigrationConfigConsensus {}

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcashMigrationConfigPrivate;

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    EcashMigrationCommonInit,
    EcashMigrationGenParams,
    EcashMigrationGenParamsLocal,
    EcashMigrationGenParamsConsensus,
    EcashMigrationConfig,
    EcashMigrationConfigPrivate,
    EcashMigrationConfigConsensus,
    EcashMigrationClientConfig
);
