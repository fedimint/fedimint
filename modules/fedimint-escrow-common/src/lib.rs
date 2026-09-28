use std::fmt;

use fedimint_core::bitcoin::hashes::{Hash, HashEngine, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::{Amount, anyhow, hex, plugin_types_trait_impl_common};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::config::EscrowClientConfig;

pub mod config;

pub const KIND: ModuleKind = ModuleKind::from_static_str("escrow");

pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(1, 0);

/// Splits are expressed in basis points (parts per 10,000)
pub const SPLIT_BPS_DENOMINATOR: u16 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Encodable, Decodable)]
pub struct EscrowId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Encodable, Decodable)]
pub struct ContractHash(pub [u8; 32]);

impl AsRef<[u8]> for EscrowId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ContractHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for EscrowId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for EscrowId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;

        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;

        Ok(EscrowId(arr))
    }
}

impl Serialize for ContractHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for ContractHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;

        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;

        Ok(ContractHash(arr))
    }
}

#[derive(Debug, Clone, Serialize, Hash, Eq, PartialEq, Deserialize, Encodable, Decodable)]
pub struct EscrowContract {
    pub escrow_id: EscrowId,
    pub funder_key: PublicKey,
    pub recipient_key: PublicKey,
    pub arbiter_key: PublicKey,
    pub amount: Amount,
    pub arbiter_fee: Amount,
    pub contract_hash: ContractHash,
    pub timeout: u64,
    pub federation_id: FederationId,
    pub status: EscrowStatus,
    pub resolution_timeout: u64,
    pub default_fallback: FallbackPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Hash, Eq, PartialEq, Deserialize, Encodable, Decodable)]
pub enum FallbackPolicy {
    Refund,
    Split {
        funder_split_bps: u16,
        recipient_split_bps: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowTransition {
    FunderRelease,
    ArbiterEngaged,
    ArbiterOutcome(Outcome),
    Fallback,
}

impl EscrowContract {
    pub fn transition(&mut self, transition: EscrowTransition) -> Result<(), EscrowInputError> {
        let new_status = match (&self.status, transition) {
            // Funder can release an active contract.
            (EscrowStatus::Active, EscrowTransition::FunderRelease) => EscrowStatus::Released,

            // Active -> Disputed transitions by arbiter engagement.
            (EscrowStatus::Active, EscrowTransition::ArbiterEngaged) => EscrowStatus::Disputed,

            // Arbiter can only resolve an already-disputed contract.
            (EscrowStatus::Disputed, EscrowTransition::ArbiterOutcome(outcome)) => match outcome {
                Outcome::Release => EscrowStatus::Released,
                Outcome::Refund => EscrowStatus::Refunded,
                Outcome::Split { .. } => EscrowStatus::Split,
            },

            (EscrowStatus::Active, EscrowTransition::Fallback) => match self.default_fallback {
                FallbackPolicy::Refund => EscrowStatus::Refunded,
                FallbackPolicy::Split { .. } => EscrowStatus::Split,
            },

            _ => return Err(EscrowInputError::InvalidStateTransition),
        };

        self.status = new_status;
        Ok(())
    }
    pub fn engage_message(&self) -> EscrowMessage {
        EscrowMessage::ArbiterEngaged {
            escrow_id: self.escrow_id,
            federation_id: self.federation_id,
            contract_hash: self.contract_hash,
        }
    }

    pub fn resolution_message(&self, outcome: Outcome) -> EscrowMessage {
        EscrowMessage::Resolution {
            escrow_id: self.escrow_id,
            federation_id: self.federation_id,
            outcome,
            contract_hash: self.contract_hash,
        }
    }
}

#[derive(Debug, Clone, Serialize, Hash, Eq, PartialEq, Deserialize, Encodable, Decodable)]
pub enum EscrowStatus {
    Active,
    Released,
    Refunded,
    Disputed,
    Split,
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
    Release,
    Refund,
    Split {
        funder_split_bps: u16,
        recipient_split_bps: u16,
    },
}

use std::str::FromStr;

impl FromStr for Outcome {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "release" => Ok(Outcome::Release),
            "refund" => Ok(Outcome::Refund),
            other => {
                let rest = other
                    .strip_prefix("split:")
                    .ok_or_else(|| anyhow::anyhow!(
                        "invalid outcome '{s}', expected 'release', 'refund', or 'split:<funder_bps>:<recipient_bps>'"
                    ))?;
                let mut parts = rest.split(':');
                let funder_split_bps: u16 = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing funder_split"))?
                    .parse()?;
                let recipient_split_bps: u16 = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing recipient_split"))?
                    .parse()?;
                Ok(Outcome::Split {
                    funder_split_bps,
                    recipient_split_bps,
                })
            }
        }
    }
}

impl FromStr for FallbackPolicy {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "refund" => Ok(FallbackPolicy::Refund),
            other => {
                let rest = other
                    .strip_prefix("split:")
                    .ok_or_else(|| anyhow::anyhow!(
                        "invalid fallback '{s}', expected 'refund' or 'split:<funder_bps>:<recipient_bps>'"
                    ))?;
                let mut parts = rest.split(':');
                let funder_split_bps: u16 = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing funder_split"))?
                    .parse()?;
                let recipient_split_bps: u16 = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing recipient_split"))?
                    .parse()?;
                Ok(FallbackPolicy::Split {
                    funder_split_bps,
                    recipient_split_bps,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Resolution {
    FunderRelease {
        funder_signature: Signature,
    },
    ArbiterEngaged {
        disputant_pubkey: PublicKey,
        disputant_signature: Signature,
        arbiter_signature: Signature,
    },
    ArbiterOutcome {
        arbiter_signature: Signature,
        outcome: Outcome,
        claimer_pubkey: PublicKey,
    },
    ArbiterFeeClaim {
        arbiter_claim_pubkey: PublicKey,
        arbiter_signature: Signature,
    },
    ResolveFallbackPolicy {
        claimer_pubkey: PublicKey,
        fallback: FallbackPolicy,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EscrowMessage {
    Resolution {
        escrow_id: EscrowId,
        federation_id: FederationId,
        outcome: Outcome,
        contract_hash: ContractHash,
    },

    ArbiterEngaged {
        escrow_id: EscrowId,
        federation_id: FederationId,
        contract_hash: ContractHash,
    },

    ArbiterFeeClaim {
        escrow_id: EscrowId,
        fee_amount: Amount,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct PendingArbiterFeePool {
    pub escrow_id: EscrowId,
    pub remaining_arbiters: Vec<PublicKey>,
    pub remaining_amount: Amount,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct PendingSplitPool {
    pub escrow_id: EscrowId,
    pub claimant_key: PublicKey,
    pub amount: Amount,
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
    #[error("Invalid funder signature")]
    InvalidFunderSignature,
    #[error("Invalid arbiter signature")]
    InvalidArbiterSignature,
    #[error("Timeout not reached")]
    TimeoutNotReached,
    #[error("Contract hash not matched")]
    ContractHashMismatch,
    #[error("Invalid contract state transition")]
    InvalidStateTransition,
    #[error("Contract is under dispute; funder release is no longer valid")]
    ContractDisputed,
    #[error("Contract not disputed")]
    ContractNotDisputed,
    #[error("No pending split claim for this key")]
    NoPendingSplitClaim,
    #[error("Invalid split ratio")]
    InvalidSplitRatio,
    #[error("Fallback resolution is not yet available")]
    FallbackNotAvailable,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum EscrowOutputError {
    #[error("Contract hash mismatch")]
    ContractHashMismatch,
    #[error("Contract already exists")]
    AlreadyExists,
    #[error("Identical input keys found")]
    InvalidInputs,
    #[error("Internal error: {0}")]
    InternalError(String),
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
        write!(f, "EscrowOutputOutcome")
    }
}

impl std::fmt::Display for EscrowConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EscrowConsensusItem")
    }
}

impl std::fmt::Display for EscrowOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EscrowOutput")
    }
}

impl std::fmt::Display for EscrowInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EscrowInput")
    }
}

pub const GET_CONTRACT_ENDPOINT: &str = "get_contract";
pub const GET_PENDING_ARBITER_FEE_ENDPOINT: &str = "get_pending_arbiter_fee";
pub const LIST_CONTRACT_BY_KEY_ENDPOINT: &str = "list_contract_by_key";

pub const GET_CONTRACT_DOMAIN: &str = "get_contract";
pub const GET_PENDING_FEE_DOMAIN: &str = "get_pending_fee";
pub const LIST_CONTRACT_DOMAIN: &str = "list_contracts";

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct GetContractParams {
    pub escrow_id: EscrowId,
    pub pubkey: PublicKey,
    pub sign: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct GetPendinFeeParams {
    pub escrow_id: EscrowId,
    pub pubkey: PublicKey,
    pub sign: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct ListContractParams {
    pub pubkey: PublicKey,
    pub federation_id: FederationId,
    pub sig: Signature,
}

fn compute_resolution_message(
    federation_id: &FederationId,
    escrow_id: &EscrowId,
    outcome: &Outcome,
    contract_hash: &ContractHash,
    engine: &mut sha256::HashEngine,
) {
    engine.input(b"escrow_resolution_message");
    engine.input(&federation_id.0.to_byte_array());
    engine.input(&escrow_id.0);
    match outcome {
        Outcome::Release => engine.input(&[0u8]),
        Outcome::Refund => engine.input(&[1u8]),
        Outcome::Split {
            funder_split_bps,
            recipient_split_bps,
        } => {
            engine.input(&[2u8]);
            engine.input(&funder_split_bps.to_le_bytes());
            engine.input(&recipient_split_bps.to_le_bytes());
        }
    }
    engine.input(&contract_hash.0);
}

#[allow(clippy::too_many_arguments)]
pub fn compute_contract_hash(
    funder_key: &PublicKey,
    recipient_key: &PublicKey,
    arbiter_key: &PublicKey,
    amount: &Amount,
    timeout: &u64,
    federation_id: &FederationId,
    resolution_timeout: &u64,
    default_fallback: &FallbackPolicy,
) -> ContractHash {
    let mut engine = sha256::HashEngine::default();
    engine.input(b"escrow_contract_hash");
    engine.input(&funder_key.serialize());
    engine.input(&recipient_key.serialize());
    engine.input(&arbiter_key.serialize());
    engine.input(&amount.msats.to_le_bytes());
    engine.input(&timeout.to_le_bytes());
    engine.input(&federation_id.0.to_byte_array());
    engine.input(&resolution_timeout.to_le_bytes());
    default_fallback
        .consensus_encode(&mut engine)
        .expect("hash engine writes can't fail");
    ContractHash(sha256::Hash::from_engine(engine).to_byte_array())
}

pub fn compute_proof_message(
    domain: &[u8],
    payload: &[u8],
    pubkey: &PublicKey,
    federation_id: Option<&FederationId>,
) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    engine.input(b"escrow_proof");
    engine.input(domain);
    engine.input(payload);
    engine.input(&pubkey.serialize());
    engine.input(&(federation_id.is_some() as u8).to_le_bytes());
    if let Some(id) = federation_id {
        engine.input(&id.0.to_byte_array());
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn compute_escrow_message(message: &EscrowMessage) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();

    match message {
        EscrowMessage::Resolution {
            escrow_id,
            federation_id,
            outcome,
            contract_hash,
        } => compute_resolution_message(
            federation_id,
            escrow_id,
            outcome,
            contract_hash,
            &mut engine,
        ),

        EscrowMessage::ArbiterEngaged {
            escrow_id,
            federation_id,
            contract_hash,
        } => {
            engine.input(b"arbiter_engaged");
            engine.input(&escrow_id.0);
            engine.input(&federation_id.0.to_byte_array());
            engine.input(&contract_hash.0);
        }

        EscrowMessage::ArbiterFeeClaim {
            escrow_id,
            fee_amount,
        } => {
            engine.input(b"arbiter_fee_claim");
            engine.input(&escrow_id.0);
            engine.input(&fee_amount.msats.to_le_bytes());
        }
    }

    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn validate_split_bps(funder_split: u16, recipient_split: u16) -> bool {
    u32::from(funder_split) + u32::from(recipient_split) == u32::from(SPLIT_BPS_DENOMINATOR)
}
