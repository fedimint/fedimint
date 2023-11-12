use std::fmt;

use config::DummyClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, Amount};
use secp256k1::{KeyPair, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client and server configuration
pub mod config;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("dummy");

/// Modules are non-compatible with older versions
pub const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion(0);

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DummyConsensusItem;

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct DummyInput {
    pub amount: Amount,
    /// Associate the input with a user's pubkey
    pub account: XOnlyPublicKey,
}

/// Output for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct DummyOutput {
    pub amount: Amount,
    /// Associate the output with a user's pubkey
    pub account: XOnlyPublicKey,
}

/// Information needed by a client to update output funds
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct DummyOutputOutcome(pub Amount, pub XOnlyPublicKey);

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum DummyInputError {
    #[error("Not enough funds")]
    NotEnoughFunds,
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum DummyOutputError {}

/// Contains the types defined above
pub struct DummyModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    DummyModuleTypes,
    DummyClientConfig,
    DummyInput,
    DummyOutput,
    DummyOutputOutcome,
    DummyConsensusItem,
    DummyInputError,
    DummyOutputError
);

#[derive(Debug)]
pub struct DummyCommonInit;

impl CommonModuleInit for DummyCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = DummyClientConfig;

    fn decoder() -> Decoder {
        DummyModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for DummyClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyClientConfig")
    }
}
impl fmt::Display for DummyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyInput {}", self.amount)
    }
}

impl fmt::Display for DummyOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutput {}", self.amount)
    }
}

impl fmt::Display for DummyOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputOutcome")
    }
}

impl fmt::Display for DummyConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyConsensusItem")
    }
}

/// A special key that creates assets for a test/example
const FED_SECRET_PHRASE: &str = "Money printer go brrr...........";

const BROKEN_FED_SECRET_PHRASE: &str = "Money printer go <boom>........!";

pub fn fed_public_key() -> XOnlyPublicKey {
    fed_key_pair().x_only_public_key().0
}

pub fn fed_key_pair() -> KeyPair {
    KeyPair::from_seckey_slice(&Secp256k1::new(), FED_SECRET_PHRASE.as_bytes()).expect("32 bytes")
}

pub fn broken_fed_public_key() -> XOnlyPublicKey {
    broken_fed_key_pair().x_only_public_key().0
}

// Like fed, but with a broken accounting
pub fn broken_fed_key_pair() -> KeyPair {
    KeyPair::from_seckey_slice(&Secp256k1::new(), BROKEN_FED_SECRET_PHRASE.as_bytes())
        .expect("32 bytes")
}
