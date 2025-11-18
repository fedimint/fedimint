#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::fmt;

use bitcoin_hashes::sha256;
use config::EcashMigrationClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{Amount, plugin_types_trait_impl_common};
use fedimint_mint_common::{Nonce, Note};
use serde::{Deserialize, Serialize};
use tbs::AggregatePublicKey;
use thiserror::Error;

// Common contains types shared by both the client and server

// The client and server configuration
pub mod config;

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

/// Hash of the spend book for consensus verification
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpendBookHash(pub sha256::Hash);

impl fmt::Display for SpendBookHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Public keys from the origin federation for verifying note signatures
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct OriginFederationKeys {
    /// Threshold public keys for each denomination from the origin mint
    pub public_keys: Vec<(Amount, AggregatePublicKey)>,
}

/// Current phase of a migration transfer
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum TransferPhase {
    /// Transfer created, waiting for spend book upload
    Initializing,
    /// Spend book being uploaded
    Uploading,
    /// Upload complete, ready for activation
    ReadyForActivation,
    /// Active, users can redeem
    Active,
}

impl fmt::Display for TransferPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferPhase::Initializing => write!(f, "Initializing"),
            TransferPhase::Uploading => write!(f, "Uploading"),
            TransferPhase::ReadyForActivation => write!(f, "ReadyForActivation"),
            TransferPhase::Active => write!(f, "Active"),
        }
    }
}

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EcashMigrationConsensusItem {
    /// Activate a transfer after verifying spend book hash and total amount
    ActivateTransfer {
        transfer_id: TransferId,
        spend_book_hash: SpendBookHash,
        total_amount: Amount,
    },
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
    /// This module does not produce outputs
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
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
    /// Transfer does not exist
    #[error("Transfer {0} does not exist")]
    InvalidTransfer(TransferId),
    /// Transfer is not in active phase
    #[error("Transfer {0} is not active (current phase: {1})")]
    TransferNotActive(TransferId, TransferPhase),
    /// Note has already been redeemed
    #[error("Note with nonce {0} has already been redeemed")]
    AlreadyRedeemed(Nonce),
    /// Note not found in spend book
    #[error("Note with nonce {0} not found in spend book")]
    NotInSpendBook(Nonce),
    /// Invalid note signature
    #[error("Invalid signature on note")]
    InvalidSignature,
    /// Amount mismatch
    #[error("Amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: Amount, actual: Amount },
    /// Unknown input variant
    #[error("Unknown input variant {0}")]
    UnknownInputVariant(u64),
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EcashMigrationOutputError {
    #[error("This module does not support outputs")]
    NotSupported,
}

/// API: Request to create a new transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTransferRequest {
    /// Secret for authenticating future operations
    pub secret: String,
    /// Origin federation public keys
    pub origin_keys: OriginFederationKeys,
}

/// API: Response from creating a transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTransferResponse {
    pub transfer_id: TransferId,
}

/// API: Request to upload a batch of spend book entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSpendBookBatchRequest {
    pub transfer_id: TransferId,
    /// HMAC of the secret for authentication
    pub auth_hmac: String,
    /// Batch of spent nonces with their amounts
    pub entries: Vec<(Nonce, Amount)>,
}

/// API: Response from uploading spend book batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSpendBookBatchResponse {
    pub total_entries: u64,
    pub total_amount: Amount,
}

/// API: Request to finalize spend book upload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeUploadRequest {
    pub transfer_id: TransferId,
    pub auth_hmac: String,
}

/// API: Response from finalizing upload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeUploadResponse {
    pub spend_book_hash: SpendBookHash,
    pub total_amount: Amount,
}

/// API: Request to activate redemption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestActivationRequest {
    pub transfer_id: TransferId,
    pub auth_hmac: String,
}

/// API: Request to get transfer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransferStatusRequest {
    pub transfer_id: TransferId,
}

/// API: Response with transfer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransferStatusResponse {
    pub phase: TransferPhase,
    pub total_entries: u64,
    pub total_amount: Amount,
    pub spend_book_hash: Option<SpendBookHash>,
    pub redeemed_count: u64,
    pub redeemed_amount: Amount,
}

/// API: Request to get spend book hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSpendBookHashRequest {
    pub transfer_id: TransferId,
}

/// API: Response with spend book hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSpendBookHashResponse {
    pub spend_book_hash: SpendBookHash,
    pub total_amount: Amount,
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
                    "RedeemOriginEcash(transfer={}, note={}, amount={})",
                    transfer_id, note, amount
                )
            }
            EcashMigrationInput::Default { variant, .. } => {
                write!(f, "EcashMigrationInput::Default(variant={})", variant)
            }
        }
    }
}

impl fmt::Display for EcashMigrationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcashMigrationOutput::Default { variant, .. } => {
                write!(f, "EcashMigrationOutput::Default(variant={})", variant)
            }
        }
    }
}

impl fmt::Display for EcashMigrationOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcashMigrationOutputOutcome::Default { variant, .. } => {
                write!(
                    f,
                    "EcashMigrationOutputOutcome::Default(variant={})",
                    variant
                )
            }
        }
    }
}

impl fmt::Display for EcashMigrationConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcashMigrationConsensusItem::ActivateTransfer {
                transfer_id,
                spend_book_hash,
                total_amount,
            } => {
                write!(
                    f,
                    "ActivateTransfer(transfer={}, hash={}, amount={})",
                    transfer_id, spend_book_hash, total_amount
                )
            }
            EcashMigrationConsensusItem::Default { variant, .. } => {
                write!(
                    f,
                    "EcashMigrationConsensusItem::Default(variant={})",
                    variant
                )
            }
        }
    }
}
