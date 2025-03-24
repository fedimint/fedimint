#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! # Lightning Module
//!
//! This module allows to atomically and trustlessly (in the federated trust
//! model) interact with the Lightning network through a Lightning gateway.

extern crate core;

pub mod config;
pub mod contracts;
pub mod endpoint_constants;
pub mod gateway_api;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::schnorr::Signature;
use config::LightningClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{OutPoint, extensible_associated_module_type, plugin_types_trait_impl_common};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tpe::AggregateDecryptionKey;

use crate::contracts::{IncomingContract, OutgoingContract};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Bolt11InvoiceDescription {
    Direct(String),
    Hash(sha256::Hash),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub enum LightningInvoice {
    Bolt11(Bolt11Invoice),
}

pub const KIND: ModuleKind = ModuleKind::from_static_str("lnv2");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(1, 0);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractId(pub sha256::Hash);

extensible_associated_module_type!(
    LightningInput,
    LightningInputV0,
    UnknownLightningInputVariantError
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningInputV0 {
    Outgoing(OutPoint, OutgoingWitness),
    Incoming(OutPoint, AggregateDecryptionKey),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum OutgoingWitness {
    Claim([u8; 32]),
    Refund,
    Cancel(Signature),
}

impl std::fmt::Display for LightningInputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningInputV0",)
    }
}

extensible_associated_module_type!(
    LightningOutput,
    LightningOutputV0,
    UnknownLightningOutputVariantError
);

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutputV0 {
    Outgoing(OutgoingContract),
    Incoming(IncomingContract),
}

impl std::fmt::Display for LightningOutputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningOutputV0")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct LightningOutputOutcome;

impl std::fmt::Display for LightningOutputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningOutputOutcome")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum LightningInputError {
    #[error("The lightning input version is not supported by this federation")]
    UnknownInputVariant(#[from] UnknownLightningInputVariantError),
    #[error("No contract found for given ContractId")]
    UnknownContract,
    #[error("The preimage is invalid")]
    InvalidPreimage,
    #[error("The contracts locktime has passed")]
    Expired,
    #[error("The contracts locktime has not yet passed")]
    NotExpired,
    #[error("The aggregate decryption key is invalid")]
    InvalidDecryptionKey,
    #[error("The forfeit signature is invalid")]
    InvalidForfeitSignature,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum LightningOutputError {
    #[error("The lightning input version is not supported by this federation")]
    UnknownOutputVariant(#[from] UnknownLightningOutputVariantError),
    #[error("The contract is invalid")]
    InvalidContract,
    #[error("The contract is expired")]
    ContractExpired,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub enum LightningConsensusItem {
    BlockCountVote(u64),
    UnixTimeVote(u64),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl std::fmt::Display for LightningConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningConsensusItem")
    }
}

#[derive(Debug)]
pub struct LightningCommonInit;

impl CommonModuleInit for LightningCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = LightningClientConfig;

    fn decoder() -> Decoder {
        LightningModuleTypes::decoder()
    }
}

pub struct LightningModuleTypes;

plugin_types_trait_impl_common!(
    KIND,
    LightningModuleTypes,
    LightningClientConfig,
    LightningInput,
    LightningOutput,
    LightningOutputOutcome,
    LightningConsensusItem,
    LightningInputError,
    LightningOutputError
);
