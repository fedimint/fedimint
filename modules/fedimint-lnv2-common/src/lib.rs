//! # Lightning Module
//!
//! This module allows to atomically and trustlessly (in the federated trust
//! model) interact with the Lightning network through a Lightning gateway.

extern crate core;

pub mod config;
pub mod contracts;

use std::collections::BTreeMap;

use bitcoin_hashes::sha256;
use config::LightningClientConfig;
use fedimint_client::sm::Context;
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, Amount, PeerId};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tpe::{AggregateDecryptionKey, AggregatePublicKey, DecryptionKeyShare, PublicKeyShare};

use crate::contracts::{IncomingContract, OutgoingContract};

pub const KIND: ModuleKind = ModuleKind::from_static_str("lnv2");
const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion { major: 0, minor: 0 };

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractId(pub sha256::Hash);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Witness {
    Outgoing(ContractId, OutgoingWitness),
    Incoming(ContractId, AggregateDecryptionKey),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum OutgoingWitness {
    Claim([u8; 32]),
    Refund,
    Cancel(Signature),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct LightningInput {
    pub amount: Amount,
    pub witness: Witness,
}

impl std::fmt::Display for LightningInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningInput",)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutput {
    Outgoing(OutgoingContract),
    Incoming(IncomingContract),
}

impl LightningOutput {
    pub fn amount(&self) -> Amount {
        match self {
            LightningOutput::Outgoing(contract) => contract.amount,
            LightningOutput::Incoming(contract) => contract.commitment.amount,
        }
    }
}

impl std::fmt::Display for LightningOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningOutput")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutputOutcome {
    Outgoing,
    Incoming(DecryptionKeyShare),
}

impl std::fmt::Display for LightningOutputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningOutputOutcome")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum LightningInputError {
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
    #[error("The contract is invalid")]
    InvalidContract,
    #[error("The contract is expired")]
    ContractExpired,
    #[error("A contract with this ContractId already exists")]
    ContractAlreadyExists,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub enum LightningConsensusItem {
    BlockCountVote(u64),
    UnixTimeVote(u64),
}

impl std::fmt::Display for LightningConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningConsensusItem")
    }
}

#[derive(Debug)]
pub struct LightningCommonInit;

impl CommonModuleInit for LightningCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = LightningClientConfig;

    fn decoder() -> Decoder {
        LightningModuleTypes::decoder()
    }
}

pub struct LightningModuleTypes;

plugin_types_trait_impl_common!(
    LightningModuleTypes,
    LightningClientConfig,
    LightningInput,
    LightningOutput,
    LightningOutputOutcome,
    LightningConsensusItem,
    LightningInputError,
    LightningOutputError
);

#[derive(Debug, Clone)]
pub struct LightningClientContext {
    pub decoder: Decoder,
    pub federation_id: FederationId,
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
}

impl Context for LightningClientContext {}
