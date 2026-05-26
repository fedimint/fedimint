use std::time::Duration;

use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::config::FederationId;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::anyhow;
use fedimint_core::{Amount, plugin_types_trait_impl_common};
use fedimint_core::bitcoin::hashes::{Hash, HashEngine};

use std::fmt;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use crate::config::EscrowClientConfig;

pub mod config;

pub const KIND: ModuleKind = ModuleKind::from_static_str("escrow");

pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(1, 0);

#[derive(Debug,Clone,Copy,PartialEq,Eq,Hash,Serialize,Deserialize,Encodable,Decodable)]
pub struct EscrowId(pub [u8; 32]);

#[derive(Debug,Clone,Serialize,Hash,Eq, PartialEq,Deserialize,Encodable,Decodable)]
pub struct EscrowContract {
    pub escrow_id: EscrowId,
    pub buyer_key: PublicKey,
    pub seller_key: PublicKey,
    pub arbiter_key: PublicKey,
    pub amount: Amount,
    pub arbiter_fee:Amount,
    pub contract_hash: [u8; 32],
    pub timeout: Duration,
    pub federation_id: FederationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct EscrowOutput {
    pub contract: EscrowContract,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EscrowOutputOutcome;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EscrowInput {
    pub escrow_id: EscrowId,
    pub resolution: Resolution,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Outcome {
    Release=0,
    Refund=1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Resolution {
    BuyerRelease {
        buyer_signature: Signature,
    },
    ArbiterOutcome {
        arbiter_signature: Signature,
        outcome: Outcome,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EscrowConsensusItem {
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EscrowInputError {
    #[error("Contract not found")]
    ContractNotFound,
    #[error("Invalid buyer signature")]
    InvalidBuyerSignature,
    #[error("Invalid arbiter signature")]
    InvalidArbiterSignature,
    #[error("Timeout not reached")]
    TimeoutNotReached,
    #[error("Contract hash not matched")]
    ContractHashMismatch
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EscrowOutputError {
    #[error("Contract hash mismatch")]
    ContractHashMismatch,
    #[error("Contract already exists")]
    AlreadyExists,
}

pub struct EscrowModuleTypes;

plugin_types_trait_impl_common!(
    KIND,
    EscrowModuleTypes,
    EscrowClientConfig,
    EscrowInput,
    EscrowOutput,
    EscrowOutputOutcome,
    EscrowConsensusItem,
    EscrowInputError,
    EscrowOutputError
);

#[derive(Debug)]
pub struct EscrowCommonInit;

impl CommonModuleInit for EscrowCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;
    type ClientConfig = EscrowClientConfig;
    fn decoder() -> fedimint_core::core::Decoder {
        EscrowModuleTypes::decoder_builder().build()
    }
}

impl std::fmt::Display for EscrowOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,"EscrowOutputOutcome")
    }
}

impl std::fmt::Display for EscrowConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,"EscrowConsensusItem")
    }
}

impl std::fmt::Display for EscrowOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,"EscrowOutput")
    }
}

impl std::fmt::Display for EscrowInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,"EscrowInput")
    }
}

pub const GET_CONTRACT_ENDPOINT: &str = "get_contract";

pub fn compute_resolution_message(
    federation_id:&FederationId,
    escrow_id:&EscrowId,
    outcome:&Outcome,
    contract_hash: &[u8; 32]
)->[u8;32]{
    let mut engine=sha256::HashEngine::default();
    let outcome_byte = match outcome {
        Outcome::Release => 0u8,
        Outcome::Refund => 1u8,
    };
    engine.input(b"escrow_resolution_message_v1");
    engine.input(&federation_id.0.to_byte_array());
    engine.input(&escrow_id.0);
    engine.input(&[outcome_byte]);
    engine.input(contract_hash);
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn compute_contract_hash(
    buyer_key:&PublicKey,
    seller_key:&PublicKey,
    arbiter_key:&PublicKey,
    amount:&Amount,
    timeout:&Duration,
    federation_id:&FederationId
)->[u8;32]{
    let mut engine=sha256::HashEngine::default();
    engine.input(b"escrow_contract_hash");
    engine.input(&buyer_key.serialize());
    engine.input(&seller_key.serialize());
    engine.input(&arbiter_key.serialize());
    engine.input(&amount.msats.to_le_bytes());
    engine.input(&timeout.as_secs().to_le_bytes());
    engine.input(&federation_id.0.to_byte_array());
    sha256::Hash::from_engine(engine).to_byte_array()
}