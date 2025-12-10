use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use serde::{Deserialize, Serialize};

use crate::UnknownCommonInit;

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnknownConfig {
    pub private: UnknownConfigPrivate,
    pub consensus: UnknownConfigConsensus,
}

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct UnknownClientConfig;

/// Locally unencrypted config unique to each member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct UnknownConfigLocal;

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct UnknownConfigConsensus;

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnknownConfigPrivate;

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    UnknownCommonInit,
    UnknownConfig,
    UnknownConfigPrivate,
    UnknownConfigConsensus,
    UnknownClientConfig
);
