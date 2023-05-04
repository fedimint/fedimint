use std::fmt;

use async_trait::async_trait;
use fedimint_core::config::ModuleGenParams;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::SerdeSignatureShare;
use fedimint_core::module::{CommonModuleGen, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, Amount};
use secp256k1::{KeyPair, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client and server configuration
pub mod config;

/// Unique name for this module
const KIND: ModuleKind = ModuleKind::from_static_str("dummy");

/// Modules are non-compatible with older versions
pub const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion(0);

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum DummyConsensusItem {
    /// User's message sign request signed by a single peer
    Sign(String, SerdeSignatureShare),
}

/// Parameters necessary to generate this module's configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyConfigGenParams {
    pub tx_fee: Amount,
}

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
// TODO: Move to server lib?
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum DummyError {
    #[error("Not enough funds")]
    NotEnoughFunds,
}

/// Contains the types defined above
pub struct DummyModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    DummyModuleTypes,
    DummyInput,
    DummyOutput,
    DummyOutputOutcome,
    DummyConsensusItem
);

// TODO: Boilerplate-code
impl ModuleGenParams for DummyConfigGenParams {}

// TODO: Boilerplate-code
#[derive(Debug)]
pub struct DummyCommonGen;

// TODO: Boilerplate-code
#[async_trait]
impl CommonModuleGen for DummyCommonGen {
    const KIND: ModuleKind = KIND;

    fn decoder() -> Decoder {
        DummyModuleTypes::decoder_builder().build()
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

pub fn fed_public_key() -> XOnlyPublicKey {
    fed_key_pair().x_only_public_key().0
}

pub fn fed_key_pair() -> KeyPair {
    KeyPair::from_seckey_slice(&Secp256k1::new(), FED_SECRET_PHRASE.as_bytes()).expect("32 bytes")
}
