use std::fmt;
use std::str::FromStr;

use fedimint_core::bitcoin::hashes::{Hash, HashEngine, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::{Amount, hex, plugin_types_trait_impl_common};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::config::EscrowClientConfig;

pub mod config;
pub mod endpoint_constants;
pub mod rules;

#[cfg(test)]
mod tests;

pub const KIND: ModuleKind = ModuleKind::from_static_str("escrow");

pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(1, 0);

/// Splits are expressed in basis points (parts per 10,000)
pub const SPLIT_BPS_DENOMINATOR: u16 = 10_000;

const MIN_PERIOD: u64 = 10 * 60;

/// A contract has room for 32 fee keys, so a consortium cannot be bigger
pub const MAX_FEE_PARTICIPANTS: usize = 32;

pub const DEFAULT_PAGE_LIMIT: u32 = 50;

/// Unique identifier for an escrow contract.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Encodable, Decodable)]
pub struct EscrowId(pub [u8; 32]);

/// Hash representing the immutable terms of an escrow contract.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Encodable, Decodable)]
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

impl EscrowId {
    pub fn build(contract_hash: &ContractHash) -> anyhow::Result<Self> {
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("failed to generate nonce"))?;

        let escrow_id = {
            let mut engine = sha256::HashEngine::default();
            engine.input(b"escrow_id");
            engine.input(&contract_hash.0);
            engine.input(&nonce);
            EscrowId(sha256::Hash::from_engine(engine).to_byte_array())
        };
        Ok(escrow_id)
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
    pub arbiter_fee_key: Vec<PublicKey>,
    pub amount: Amount,
    pub arbiter_fee: Amount,
    pub contract_hash: ContractHash,
    pub timeout: u64,
    pub federation_id: FederationId,
    pub status: EscrowStatus,
    pub resolution_period: u64,
    pub default_fallback: FallbackPolicy,
}

/// Defines the policy applied when an escrow dispute
/// is not resolved within the allowed resolution period.
#[derive(Debug, Clone, Serialize, Hash, Eq, PartialEq, Deserialize, Encodable, Decodable)]
pub enum FallbackPolicy {
    Refund,
    Split {
        funder_split_bps: u16,
        recipient_split_bps: u16,
    },
    SwapArbiter {
        arbiter_key: PublicKey,
        arbiter_fee_key: Vec<PublicKey>,
        arbiter_fee: Amount,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowTransition {
    FunderRelease,
    ArbiterEngaged { resolve_by: u64 },
    ArbiterOutcome(Outcome),
    SwapArbiter { resolve_by: u64 },
    Fallback,
}

impl EscrowContract {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        escrow_id: EscrowId,
        funder_key: PublicKey,
        recipient_key: PublicKey,
        arbiter_key: PublicKey,
        arbiter_fee_key: Vec<PublicKey>,
        amount: Amount,
        arbiter_fee: Amount,
        contract_hash: ContractHash,
        timeout: u64,
        federation_id: FederationId,
        resolution_period: u64,
        default_fallback: FallbackPolicy,
        now: u64,
    ) -> Result<Self, EscrowContractValidationError> {
        let contract = Self {
            escrow_id,
            funder_key,
            recipient_key,
            arbiter_key,
            arbiter_fee_key,
            amount,
            arbiter_fee,
            contract_hash,
            timeout,
            federation_id,
            status: EscrowStatus::Active,
            resolution_period,
            default_fallback,
        };
        validate_contract_fields(&contract, now)?;

        Ok(contract)
    }

    pub fn can_swap_arbiter(&self) -> bool {
        matches!(self.status, EscrowStatus::Disputed { swapped: false, .. })
            && matches!(self.default_fallback, FallbackPolicy::SwapArbiter { .. })
    }

    /// The arbiter key that will sign the resolution
    pub fn current_arbiter_key(&self) -> &PublicKey {
        match (&self.status, &self.default_fallback) {
            (
                EscrowStatus::Disputed { swapped: true, .. },
                FallbackPolicy::SwapArbiter { arbiter_key, .. },
            ) => arbiter_key,
            _ => &self.arbiter_key,
        }
    }

    /// The current arbiter fee keys that will used to submit tx and claim
    /// fees.
    pub fn current_fee_keys(&self) -> &[PublicKey] {
        match (&self.status, &self.default_fallback) {
            (
                EscrowStatus::Disputed { swapped: true, .. },
                FallbackPolicy::SwapArbiter {
                    arbiter_fee_key, ..
                },
            ) => arbiter_fee_key,
            _ => &self.arbiter_fee_key,
        }
    }

    /// Gives current arbiter fee amount
    pub fn current_arbiter_fee(&self) -> Amount {
        match (&self.status, &self.default_fallback) {
            (
                EscrowStatus::Disputed { swapped: true, .. },
                FallbackPolicy::SwapArbiter { arbiter_fee, .. },
            ) => *arbiter_fee,
            _ => self.arbiter_fee,
        }
    }

    /// Returns the effective fallback policy that will be applied
    /// when the fallback resolution is triggered.
    pub fn effective_fallback(&self) -> FallbackPolicy {
        match &self.default_fallback {
            FallbackPolicy::SwapArbiter { .. } if !self.can_swap_arbiter() => {
                FallbackPolicy::Refund
            }
            other => other.clone(),
        }
    }

    pub fn transition(&mut self, transition: EscrowTransition) -> Result<(), EscrowInputError> {
        if let EscrowTransition::ArbiterOutcome(outcome) = transition
            && !outcome.is_valid()
        {
            return Err(EscrowInputError::InvalidSplitRatio);
        }

        let new_status = match (&self.status, transition) {
            (EscrowStatus::Active, EscrowTransition::FunderRelease) => EscrowStatus::Released,
            (EscrowStatus::Active, EscrowTransition::ArbiterEngaged { resolve_by }) => {
                EscrowStatus::Disputed {
                    resolve_by,
                    swapped: false,
                }
            }
            (EscrowStatus::Disputed { .. }, EscrowTransition::SwapArbiter { resolve_by })
                if self.can_swap_arbiter() =>
            {
                EscrowStatus::Disputed {
                    resolve_by,
                    swapped: true,
                }
            }
            (EscrowStatus::Disputed { .. }, EscrowTransition::ArbiterOutcome(outcome)) => {
                EscrowStatus::from(outcome)
            }
            (EscrowStatus::Disputed { .. }, EscrowTransition::Fallback)
                if !self.can_swap_arbiter() =>
            {
                EscrowStatus::from(Outcome::from(&self.default_fallback))
            }
            _ => return Err(EscrowInputError::InvalidStateTransition),
        };
        self.status = new_status;
        Ok(())
    }

    pub fn ensure_active(&self) -> Result<(), EscrowInputError> {
        match self.status {
            EscrowStatus::Active => Ok(()),
            EscrowStatus::Disputed { .. } => Err(EscrowInputError::ContractDisputed),
            _ => Err(EscrowInputError::ContractAlreadyResolved),
        }
    }

    /// The two parties of the escrow, without the arbiter or fee keys.
    pub fn is_party(&self, pubkey: &PublicKey) -> bool {
        x_only_eq(&self.funder_key, pubkey) || x_only_eq(&self.recipient_key, pubkey)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            EscrowStatus::Released | EscrowStatus::Refunded | EscrowStatus::Split
        )
    }

    pub fn contains_key(&self, pubkey: &PublicKey) -> bool {
        x_only_eq(&self.funder_key, pubkey)
            || x_only_eq(&self.recipient_key, pubkey)
            || x_only_eq(&self.arbiter_key, pubkey)
            || self.arbiter_fee_key.iter().any(|k| x_only_eq(k, pubkey))
            || match &self.default_fallback {
                FallbackPolicy::SwapArbiter {
                    arbiter_key,
                    arbiter_fee_key,
                    ..
                } => {
                    x_only_eq(arbiter_key, pubkey)
                        || arbiter_fee_key.iter().any(|k| x_only_eq(k, pubkey))
                }
                _ => false,
            }
    }

    pub fn all_keys(&self) -> Vec<PublicKey> {
        let mut keys = vec![self.funder_key, self.recipient_key, self.arbiter_key];
        keys.extend(self.arbiter_fee_key.iter().copied());
        if let FallbackPolicy::SwapArbiter {
            arbiter_key,
            arbiter_fee_key,
            ..
        } = &self.default_fallback
        {
            keys.push(*arbiter_key);
            keys.extend(arbiter_fee_key.iter().copied());
        }
        keys
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
    Disputed { resolve_by: u64, swapped: bool },
    Split,
}

impl From<Outcome> for EscrowStatus {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Release => EscrowStatus::Released,
            Outcome::Refund => EscrowStatus::Refunded,
            Outcome::Split { .. } => EscrowStatus::Split,
        }
    }
}

impl From<&FallbackPolicy> for Outcome {
    fn from(policy: &FallbackPolicy) -> Self {
        match policy {
            FallbackPolicy::Refund | FallbackPolicy::SwapArbiter { .. } => Outcome::Refund,
            FallbackPolicy::Split {
                funder_split_bps,
                recipient_split_bps,
            } => Outcome::Split {
                funder_split_bps: *funder_split_bps,
                recipient_split_bps: *recipient_split_bps,
            },
        }
    }
}

fn parse_split(rest: &str) -> anyhow::Result<(u16, u16)> {
    let (f, r) = rest
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("expected <funder_bps>:<recipient_bps>"))?;
    Ok((
        f.parse()
            .map_err(|e| anyhow::anyhow!("invalid funder_bps '{f}': {e}"))?,
        r.parse()
            .map_err(|e| anyhow::anyhow!("invalid recipient_bps '{r}': {e}"))?,
    ))
}

impl Outcome {
    pub fn is_valid(&self) -> bool {
        match *self {
            Outcome::Split {
                funder_split_bps,
                recipient_split_bps,
            } => validate_split_bps(funder_split_bps, recipient_split_bps),
            _ => true,
        }
    }
}

impl FallbackPolicy {
    pub fn is_valid(&self) -> bool {
        match self {
            FallbackPolicy::Split {
                funder_split_bps,
                recipient_split_bps,
            } => validate_split_bps(*funder_split_bps, *recipient_split_bps),
            _ => true,
        }
    }
}

impl FromStr for Outcome {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_ascii_lowercase();
        let outcome = match lower.as_str() {
            "release" => Outcome::Release,
            "refund" => Outcome::Refund,
            other => {
                let rest = other.strip_prefix("split:").ok_or_else(|| {
                    anyhow::anyhow!("invalid outcome '{s}', expected release, refund or split:<funder_bps>:<recipient_bps>")
                })?;
                let (funder_split_bps, recipient_split_bps) = parse_split(rest)?;
                Outcome::Split {
                    funder_split_bps,
                    recipient_split_bps,
                }
            }
        };
        anyhow::ensure!(
            outcome.is_valid(),
            "split must add up to {SPLIT_BPS_DENOMINATOR} basis points"
        );
        Ok(outcome)
    }
}

impl FromStr for FallbackPolicy {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_ascii_lowercase();
        let policy = match lower.as_str() {
            "refund" => FallbackPolicy::Refund,
            other if other.starts_with("swap:") => {
                let rest = &other["swap:".len()..];
                let mut parts = rest.splitn(3, ':');
                let arbiter_key = PublicKey::from_str(
                    parts
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("missing arbiter key"))?,
                )?;
                let fee_msats: u64 = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing arbiter fee"))?
                    .parse()?;
                let arbiter_fee_key = parts
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .filter(|k| !k.is_empty())
                    .map(PublicKey::from_str)
                    .collect::<Result<Vec<_>, _>>()?;
                FallbackPolicy::SwapArbiter {
                    arbiter_key,
                    arbiter_fee_key,
                    arbiter_fee: Amount::from_msats(fee_msats),
                }
            }
            other => {
                let rest = other.strip_prefix("split:").ok_or_else(|| {
                    anyhow::anyhow!("invalid fallback '{s}', expected refund or split:<funder_bps>:<recipient_bps>")
                })?;
                let (funder_split_bps, recipient_split_bps) = parse_split(rest)?;
                FallbackPolicy::Split {
                    funder_split_bps,
                    recipient_split_bps,
                }
            }
        };
        anyhow::ensure!(
            policy.is_valid(),
            "split must add up to {SPLIT_BPS_DENOMINATOR} basis points"
        );
        Ok(policy)
    }
}

impl fmt::Display for EscrowStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EscrowStatus::Active => "active",
            EscrowStatus::Released => "released",
            EscrowStatus::Refunded => "refunded",
            EscrowStatus::Disputed { .. } => "disputed",
            EscrowStatus::Split => "split",
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EscrowInput {
    V0(EscrowInputV0),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EscrowInputV0 {
    pub escrow_id: EscrowId,
    pub resolution: Resolution,
}

impl EscrowInput {
    pub fn new_v0(escrow_id: EscrowId, resolution: Resolution) -> Self {
        Self::V0(EscrowInputV0 {
            escrow_id,
            resolution,
        })
    }

    pub fn ensure_v0_ref(&self) -> Result<&EscrowInputV0, EscrowInputError> {
        match self {
            Self::V0(input) => Ok(input),
            Self::Default { variant, .. } => {
                Err(EscrowInputError::UnknownInputVariant { variant: *variant })
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EscrowOutput {
    V0(EscrowOutputV0),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EscrowOutputV0 {
    pub contract: EscrowContract,
}

impl EscrowOutput {
    pub fn new_v0(contract: EscrowContract) -> Self {
        Self::V0(EscrowOutputV0 { contract })
    }

    pub fn ensure_v0_ref(&self) -> Result<&EscrowOutputV0, EscrowOutputError> {
        match self {
            Self::V0(output) => Ok(output),
            Self::Default { variant, .. } => {
                Err(EscrowOutputError::UnknownOutputVariant { variant: *variant })
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EscrowOutputOutcome {
    V0(EscrowOutputOutcomeV0),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EscrowOutputOutcomeV0;

impl EscrowOutputOutcome {
    pub fn new_v0() -> Self {
        Self::V0(EscrowOutputOutcomeV0)
    }
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ClaimPool {
    pub escrow_id: EscrowId,
    pub claimer: Vec<(PublicKey, Amount)>,
}

impl ClaimPool {
    /// Removes and returns the entry for `claimer`, comparing x-only keys.
    pub fn take_claim(&mut self, claimer: &PublicKey) -> Option<(PublicKey, Amount)> {
        let idx = self
            .claimer
            .iter()
            .position(|(k, _)| x_only_eq(k, claimer))?;
        Some(self.claimer.remove(idx))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Resolution {
    FunderRelease {
        funder_signature: Signature,
    },
    ArbiterEngaged {
        disputant_pubkey: PublicKey,
        disputant_signature: Signature,
    },
    ArbiterOutcome {
        arbiter_signature: Signature,
        outcome: Outcome,
        submitter_pubkey: PublicKey,
    },
    ClaimPayout {
        claimer_pubkey: PublicKey,
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
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum EscrowConsensusItem {
    UnixTimeVote(u64),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, thiserror::Error, Encodable, Decodable)]
pub enum EscrowInputError {
    #[error("Contract not found")]
    ContractNotFound,
    #[error("Timeout not reached")]
    TimeoutNotReached,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Contract hash not matched")]
    ContractHashMismatch,
    #[error("Invalid contract state transition")]
    InvalidStateTransition,
    #[error("Contract is under dispute; funder release is no longer valid")]
    ContractDisputed,
    #[error("Contract not disputed")]
    ContractNotDisputed,
    #[error("Contract already resolved; claim the payout if available")]
    ContractAlreadyResolved,
    #[error("No pending claim")]
    NoPendingClaim,
    #[error("Invalid split ratio")]
    InvalidSplitRatio,
    #[error("Fallback resolution is not yet available")]
    FallbackNotAvailable,
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Key is not part of this escrow")]
    NotAParticipant,
    #[error("The resolution deadline has passed")]
    ResolutionDeadlinePassed,
    #[error("Unknown input version {variant}")]
    UnknownInputVariant { variant: u64 },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, thiserror::Error, Encodable, Decodable)]
pub enum EscrowOutputError {
    #[error("Contract hash mismatch")]
    ContractHashMismatch,
    #[error("Contract already exists")]
    AlreadyExists,
    #[error("Invalid input found {0}")]
    InvalidInputs(#[from] EscrowContractValidationError),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Unknown output version {variant}")]
    UnknownOutputVariant { variant: u64 },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, thiserror::Error, Encodable, Decodable)]
pub enum EscrowContractValidationError {
    #[error("amount must be greater than zero")]
    ZeroAmount,

    #[error("arbiter fee must be less than the escrow amount")]
    InvalidArbiterFee,

    #[error("invalid escrow timeout")]
    InvalidTimeout,

    #[error("invalid resolution timeout")]
    InvalidResolutionTimeout,

    #[error("invalid split ratio")]
    InvalidSplitRatio,

    #[error("participant and arbiter fee keys must be distinct")]
    DuplicateKeys,
    #[error("invalid contract state")]
    InvalidStatus,
    #[error("missing arbiter fee keys")]
    MissingArbiterFeeKeys,
    #[error("invalid input")]
    InvalidInput,
}

impl Resolution {
    pub fn kind(&self) -> &'static str {
        match self {
            Resolution::FunderRelease { .. } => "funder_release",
            Resolution::ArbiterEngaged { .. } => "arbiter_engaged",
            Resolution::ArbiterOutcome { .. } => "arbiter_outcome",
            Resolution::ClaimPayout { .. } => "claim_payout",
            Resolution::ResolveFallbackPolicy { .. } => "fallback",
        }
    }
}

impl fmt::Display for EscrowInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EscrowInput::V0(input) => write!(
                f,
                "EscrowInput({} on {})",
                input.resolution.kind(),
                input.escrow_id
            ),
            EscrowInput::Default { variant, .. } => {
                write!(f, "EscrowInput(unknown version {variant})")
            }
        }
    }
}

impl fmt::Display for EscrowOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EscrowOutput::V0(output) => write!(f, "EscrowOutput({})", output.contract.escrow_id),
            EscrowOutput::Default { variant, .. } => {
                write!(f, "EscrowOutput(unknown version {variant})")
            }
        }
    }
}

impl fmt::Display for EscrowOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EscrowOutputOutcome::V0(_) => write!(f, "EscrowOutputOutcome"),
            EscrowOutputOutcome::Default { variant, .. } => {
                write!(f, "EscrowOutputOutcome(unknown version {variant})")
            }
        }
    }
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

impl std::fmt::Display for EscrowConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            EscrowConsensusItem::UnixTimeVote(t) => {
                write!(f, "Escrow Unix Time {t}")
            }
            EscrowConsensusItem::Default { variant, ref bytes } => write!(
                f,
                "Escrow Unknown - variant: {variant}, bytes_len: {}",
                bytes.len()
            ),
        }
    }
}

/// Using xonly public key to compare the keys for schonorr signature
/// verification
pub fn x_only_eq(a: &PublicKey, b: &PublicKey) -> bool {
    x_only(a) == x_only(b)
}

pub fn x_only(pk: &PublicKey) -> fedimint_core::bitcoin::XOnlyPublicKey {
    pk.x_only_public_key().0
}

#[allow(clippy::too_many_arguments)]
pub fn compute_contract_hash(
    funder_key: &PublicKey,
    recipient_key: &PublicKey,
    arbiter_key: &PublicKey,
    arbiter_fee: &Amount,
    amount: &Amount,
    timeout: &u64,
    federation_id: &FederationId,
    resolution_period: &u64,
    arbiter_fee_key: &Vec<PublicKey>,
    default_fallback: &FallbackPolicy,
) -> ContractHash {
    let mut engine = sha256::HashEngine::default();
    engine.input(b"escrow_contract_hash");
    engine.input(&funder_key.serialize());
    engine.input(&recipient_key.serialize());
    engine.input(&arbiter_key.serialize());
    engine.input(&arbiter_fee.msats.to_le_bytes());
    engine.input(&amount.msats.to_le_bytes());
    engine.input(&timeout.to_le_bytes());
    engine.input(&federation_id.0.to_byte_array());
    engine.input(&resolution_period.to_le_bytes());
    default_fallback
        .consensus_encode(&mut engine)
        .expect("hash engine writes can't fail");
    for arbiter in arbiter_fee_key {
        engine.input(&arbiter.serialize());
    }
    ContractHash(sha256::Hash::from_engine(engine).to_byte_array())
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
    }

    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn validate_split_bps(funder_split: u16, recipient_split: u16) -> bool {
    u32::from(funder_split) + u32::from(recipient_split) == u32::from(SPLIT_BPS_DENOMINATOR)
}

/// Validates the contract fields before the escrow contract is created.
pub fn validate_contract_fields(
    contract: &EscrowContract,
    now: u64,
) -> Result<(), EscrowContractValidationError> {
    if contract.amount == Amount::ZERO {
        return Err(EscrowContractValidationError::ZeroAmount);
    }

    if contract.arbiter_fee >= contract.amount {
        return Err(EscrowContractValidationError::InvalidArbiterFee);
    }

    if contract.timeout <= now {
        return Err(EscrowContractValidationError::InvalidTimeout);
    }

    if contract.resolution_period == 0 {
        return Err(EscrowContractValidationError::InvalidResolutionTimeout);
    }

    if !contract.default_fallback.is_valid() {
        return Err(EscrowContractValidationError::InvalidSplitRatio);
    }

    if contract.status != EscrowStatus::Active {
        return Err(EscrowContractValidationError::InvalidStatus);
    }

    let mut seen = std::collections::HashSet::new();
    for key in [
        &contract.funder_key,
        &contract.recipient_key,
        &contract.arbiter_key,
    ]
    .into_iter()
    .chain(contract.arbiter_fee_key.iter())
    {
        if !seen.insert(x_only(key)) {
            return Err(EscrowContractValidationError::DuplicateKeys);
        }
    }
    if contract.arbiter_fee > Amount::ZERO && contract.arbiter_fee_key.is_empty() {
        return Err(EscrowContractValidationError::MissingArbiterFeeKeys);
    }
    if contract.arbiter_fee_key.len() > MAX_FEE_PARTICIPANTS {
        return Err(EscrowContractValidationError::InvalidInput);
    }

    if let FallbackPolicy::SwapArbiter {
        arbiter_key,
        arbiter_fee_key,
        arbiter_fee,
    } = &contract.default_fallback
    {
        if *arbiter_fee >= contract.amount {
            return Err(EscrowContractValidationError::InvalidArbiterFee);
        }
        if *arbiter_fee > Amount::ZERO && arbiter_fee_key.is_empty() {
            return Err(EscrowContractValidationError::MissingArbiterFeeKeys);
        }
        if arbiter_fee_key.len() > MAX_FEE_PARTICIPANTS {
            return Err(EscrowContractValidationError::InvalidInput);
        }
        for key in std::iter::once(arbiter_key).chain(arbiter_fee_key.iter()) {
            if !seen.insert(x_only(key)) {
                return Err(EscrowContractValidationError::DuplicateKeys);
            }
        }
    }

    if contract.resolution_period < MIN_PERIOD {
        return Err(EscrowContractValidationError::InvalidResolutionTimeout);
    }

    // A contract can produce deadlines up to timeout plus two windows (the
    // ruling window and one more after a swap). If that doesn't fit in a u64,
    // opening a dispute would fail later with an internal error
    let two_windows = contract
        .resolution_period
        .checked_mul(2)
        .ok_or(EscrowContractValidationError::InvalidResolutionTimeout)?;
    contract
        .timeout
        .checked_add(two_windows)
        .ok_or(EscrowContractValidationError::InvalidTimeout)?;

    Ok(())
}

macro_rules! hex_id {
    ($t:ident) => {
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($t), self)
            }
        }

        impl FromStr for $t {
            type Err = anyhow::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("invalid hex: {e}"))?;

                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("expected 32 bytes (64 hex characters)"))?;

                Ok(Self(arr))
            }
        }
    };
}

hex_id!(EscrowId);
hex_id!(ContractHash);
