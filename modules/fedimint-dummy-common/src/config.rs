use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, Amount};
use serde::{Deserialize, Serialize};
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{PublicKey, PublicKeySet, SecretKeyShare};

use crate::DummyCommonGen;

/// Parameters necessary to generate this module's configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyConfigGenParams {
    pub tx_fee: Amount,
}

impl Default for DummyConfigGenParams {
    fn default() -> Self {
        Self {
            tx_fee: Amount::ZERO,
        }
    }
}

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfig {
    pub private: DummyConfigPrivate,
    pub consensus: DummyConfigConsensus,
}

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct DummyClientConfig {
    /// Accessible to clients
    pub tx_fee: Amount,
    pub fed_public_key: PublicKey,
}

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct DummyConfigConsensus {
    /// Example federation threshold signing key
    pub public_key_set: PublicKeySet,
    /// Will be the same for all peers
    pub tx_fee: Amount,
}

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfigPrivate {
    /// Example private key share for a single member
    pub private_key_share: SerdeSecret<SecretKeyShare>,
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    DummyCommonGen,
    DummyConfigGenParams,
    DummyConfig,
    DummyConfigPrivate,
    DummyConfigConsensus,
    DummyClientConfig
);
