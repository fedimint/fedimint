#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::fmt;

use config::EcashMigrationClientConfig;
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
pub const KIND: ModuleKind = ModuleKind::from_static_str("ecash-migration");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EcashMigrationConsensusItem;

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EcashMigrationInput;

/// Output for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EcashMigrationOutput;

/// Information needed by a client to update output funds
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EcashMigrationOutputOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EcashMigrationInputError {
    #[error("This module does not support inputs")]
    NotSupported,
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EcashMigrationOutputError {
    #[error("This module does not support outputs")]
    NotSupported,
}

/// Contains the types defined above
pub struct EcashMigrationModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    KIND,
    EcashMigrationModuleTypes,
    EcashMigrationClientConfig,
    EcashMigrationInput,
    EcashMigrationOutput,
    EcashMigrationOutputOutcome,
    EcashMigrationConsensusItem,
    EcashMigrationInputError,
    EcashMigrationOutputError
);

#[derive(Debug)]
pub struct EcashMigrationCommonInit;

impl CommonModuleInit for EcashMigrationCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = EcashMigrationClientConfig;

    fn decoder() -> Decoder {
        EcashMigrationModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for EcashMigrationClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcashMigrationClientConfig")
    }
}
impl fmt::Display for EcashMigrationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcashMigrationInput")
    }
}

impl fmt::Display for EcashMigrationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcashMigrationOutput")
    }
}

impl fmt::Display for EcashMigrationOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcashMigrationOutputOutcome")
    }
}

impl fmt::Display for EcashMigrationConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcashMigrationConsensusItem")
    }
}
