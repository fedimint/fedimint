use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use serde::{Deserialize, Serialize};

use crate::DummyCommonInit;

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfig {
    pub private: DummyConfigPrivate,
    pub consensus: DummyConfigConsensus,
}

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct DummyClientConfig;

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct DummyConfigConsensus;

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfigPrivate;

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    DummyCommonInit,
    DummyConfig,
    DummyConfigPrivate,
    DummyConfigConsensus,
    DummyClientConfig
);
