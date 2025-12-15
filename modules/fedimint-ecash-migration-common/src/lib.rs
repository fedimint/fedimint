#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_panics_doc)]

use std::fmt;

use bitcoin_hashes::sha256;
use config::EcashMigrationClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{Amount, plugin_types_trait_impl_common};
use fedimint_mint_common::{Nonce, Note};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client and server configuration
pub mod config;

/// Merkle tree for verifiable spend book chunk uploads
pub mod merkle;

/// API types and endpoint constants
pub mod api;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("ecash-migration");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// Unique identifier for an ecash migration transfer
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct TransferId(pub u64);

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transfer({})", self.0)
    }
}

impl std::str::FromStr for TransferId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u64>().map(TransferId)
    }
}

/// Hash of the key set of the transfer
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct KeySetHash(pub sha256::Hash);

impl fmt::Display for KeySetHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EcashMigrationConsensusItem {
    /// Activate a transfer after verifying uploaded spend book matches
    /// pre-committed hash
    ActivateTransfer { transfer_id: TransferId },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum EcashMigrationInput {
    /// Redeem origin federation ecash for destination federation ecash
    RedeemOriginEcash {
        /// The transfer ID to redeem from
        transfer_id: TransferId,
        /// The note from the origin federation
        note: Note,
        /// The amount of the note
        amount: Amount,
    },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Output for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum EcashMigrationOutput {
    /// Create a new transfer, this is a transaction output so that we can
    /// charge a fee for spend book size.
    CreateTransfer(EcashMigrationCreateTransferOutput),
    /// Add funding to an existing transfer.
    FundTransfer(EcashMigrationFundTransferOutput),
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EcashMigrationCreateTransferOutput {
    /// Total number of spend book entries
    pub spend_book_entries: u64,
    /// Merkle tree info for verifiable chunk uploads
    pub spend_book_merkle_root: merkle::MerkleRoot<Nonce>,
    /// Hash of the key set
    pub key_set_hash: KeySetHash,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EcashMigrationFundTransferOutput {
    pub transfer_id: TransferId,
    pub amount: Amount,
}

/// Information needed by a client to update output funds
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum EcashMigrationOutputOutcome {
    /// This module does not produce outputs
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EcashMigrationInputError {
    /// Transfer does not exist or is not active
    #[error("Transfer {0} does not exist or is not active")]
    InvalidTransfer(TransferId),
    /// Invalid amount tier
    #[error("Invalid amount tier {0}")]
    InvalidAmountTier(Amount),
    /// Invalid note signature
    #[error("Invalid signature on note")]
    InvalidSignature,
    /// Already redeemed
    #[error("Note {0} already redeemed")]
    AlreadyRedeemed(Nonce),
    /// Underfunded transfer
    #[error("Underfunded transfer")]
    UnderfundedTransfer,
    /// Overflow
    #[error("Overflow in processing input")]
    Overflow,
    /// Unknown input variant
    #[error("Unknown input variant {0}")]
    UnknownInputVariant(u64),
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EcashMigrationOutputError {
    /// Creation fee calculation overflow
    #[error("Creation fee calculation overflow, too many spend book entries: {spend_book_entries}")]
    CreationFeeCalculationOverflow { spend_book_entries: u64 },
    #[error("Funding overflow: no, you don't have more than 21M Bitcoin ...")]
    FundingOverflow,
    /// Unknown output variant
    #[error("Unknown output variant {0}")]
    UnknownOutputVariant(u64),
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
        match self {
            EcashMigrationInput::RedeemOriginEcash {
                transfer_id,
                note,
                amount,
            } => {
                write!(
                    f,
                    "RedeemOriginEcash(transfer={transfer_id}, note={note}, amount={amount})",
                )
            }
            EcashMigrationInput::Default { variant, .. } => {
                write!(f, "EcashMigrationInput::Default(variant={variant})")
            }
        }
    }
}

impl fmt::Display for EcashMigrationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcashMigrationOutput::CreateTransfer(EcashMigrationCreateTransferOutput {
                spend_book_entries,
                spend_book_merkle_root,
                key_set_hash,
            }) => {
                write!(
                    f,
                    "EcashMigrationOutput::CreateTransfer(spend_book_entries={spend_book_entries}, spend_book_merkle_root={spend_book_merkle_root}, key_set_hash={key_set_hash:?})",
                )
            }
            EcashMigrationOutput::FundTransfer(EcashMigrationFundTransferOutput {
                transfer_id,
                amount,
            }) => {
                write!(
                    f,
                    "EcashMigrationOutput::FundTransfer(transfer={transfer_id}, amount={amount})"
                )
            }
            EcashMigrationOutput::Default { variant, .. } => {
                write!(f, "EcashMigrationOutput::Default(variant={variant})")
            }
        }
    }
}

impl fmt::Display for EcashMigrationOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcashMigrationOutputOutcome::Default { variant, .. } => {
                write!(f, "EcashMigrationOutputOutcome::Default(variant={variant})",)
            }
        }
    }
}

impl fmt::Display for EcashMigrationConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcashMigrationConsensusItem::ActivateTransfer { transfer_id } => {
                write!(f, "ActivateTransfer(transfer={transfer_id})")
            }
            EcashMigrationConsensusItem::Default { variant, .. } => {
                write!(f, "EcashMigrationConsensusItem::Default(variant={variant})",)
            }
        }
    }
}
