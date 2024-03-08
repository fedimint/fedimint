use std::fmt;

use config::EmptyClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::plugin_types_trait_impl_common;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client and server configuration
pub mod config;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("dummy");

/// Modules are non-compatible with older versions
pub const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EmptyConsensusItem;

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EmptyInput;

/// Output for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EmptyOutput;

/// Information needed by a client to update output funds
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EmptyOutputOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EmptyInputError {
    #[error("This module does not support inputs")]
    NotSupported,
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EmptyOutputError {
    #[error("This module does not support outputs")]
    NotSupported,
}

/// Contains the types defined above
pub struct EmptyModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    EmptyModuleTypes,
    EmptyClientConfig,
    EmptyInput,
    EmptyOutput,
    EmptyOutputOutcome,
    EmptyConsensusItem,
    EmptyInputError,
    EmptyOutputError
);

#[derive(Debug)]
pub struct EmptyCommonInit;

impl CommonModuleInit for EmptyCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = EmptyClientConfig;

    fn decoder() -> Decoder {
        EmptyModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for EmptyClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmptyClientConfig")
    }
}
impl fmt::Display for EmptyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmptyInput")
    }
}

impl fmt::Display for EmptyOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmptyOutput")
    }
}

impl fmt::Display for EmptyOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmptyOutputOutcome")
    }
}

impl fmt::Display for EmptyConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmptyConsensusItem")
    }
}
