use std::fmt;

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

impl fmt::Display for EscrowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
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
    ArbiterEngaged { resolve_by: u64 },
    ArbiterOutcome(Outcome),
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
    pub async fn transition(
        &mut self,
        transition: EscrowTransition,
    ) -> Result<(), EscrowInputError> {
        let new_status = match (&self.status, transition) {
            // Funder can release an active contract.
            (EscrowStatus::Active, EscrowTransition::FunderRelease) => EscrowStatus::Released,

            // Active -> Disputed transitions by arbiter engagement.
            (EscrowStatus::Active, EscrowTransition::ArbiterEngaged { resolve_by }) => {
                EscrowStatus::Disputed { resolve_by }
            }

            // Arbiter can only resolve an already-disputed contract.
            (EscrowStatus::Disputed { .. }, EscrowTransition::ArbiterOutcome(outcome)) => {
                EscrowStatus::from(outcome)
            }

            (EscrowStatus::Disputed { .. }, EscrowTransition::Fallback) => {
                EscrowStatus::from(Outcome::from(self.default_fallback))
            }

            _ => return Err(EscrowInputError::InvalidStateTransition),
        };

        self.status = new_status;
        Ok(())
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
    Disputed { resolve_by: u64 },
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

impl From<FallbackPolicy> for Outcome {
    fn from(policy: FallbackPolicy) -> Self {
        match policy {
            FallbackPolicy::Refund => Outcome::Refund,
            FallbackPolicy::Split {
                funder_split_bps,
                recipient_split_bps,
            } => Outcome::Split {
                funder_split_bps,
                recipient_split_bps,
            },
        }
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

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Release => f.write_str("release"),
            Outcome::Refund => f.write_str("refund"),
            Outcome::Split {
                funder_split_bps,
                recipient_split_bps,
            } => {
                write!(f, "split:{funder_split_bps}:{recipient_split_bps}")
            }
        }
    }
}

impl fmt::Display for FallbackPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FallbackPolicy::Refund => f.write_str("refund"),
            FallbackPolicy::Split {
                funder_split_bps,
                recipient_split_bps,
            } => {
                write!(f, "split:{funder_split_bps}:{recipient_split_bps}")
            }
        }
    }
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ClaimPool {
    pub escrow_id: EscrowId,
    pub claimer: Vec<(PublicKey, Amount)>, // Split case can have two claimers
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
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
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
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
    #[error("Contract already resolved,claim the amount if not!")]
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
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, thiserror::Error, Encodable, Decodable)]
pub enum EscrowContractValidationError {
    #[error("amount must be greater than zero")]
    ZeroAmount,

    #[error("arbiter fee must be less than the escrow amount")]
    InvalidArbiterFee,

    #[error("escrow timeout must be in the future")]
    InvalidTimeout,

    #[error("resolution timeout must be greater than zero")]
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

impl std::fmt::Display for EscrowInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EscrowInput({} on {})",
            self.resolution.kind(),
            self.escrow_id
        )
    }
}

impl std::fmt::Display for EscrowOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EscrowOutput({})", self.contract.escrow_id)
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

pub const GET_CONTRACT_ENDPOINT: &str = "get_contract";
pub const GET_CLAIM_AMOUNT_ENDPOINT: &str = "get_claim_amount";
pub const LIST_CONTRACT_BY_KEY_ENDPOINT: &str = "list_contract_by_key";

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct GetContractParams {
    pub escrow_id: EscrowId,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct GetClaimAmount {
    pub escrow_id: EscrowId,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct ListContractParams {
    pub pubkey: PublicKey,
    pub federation_id: FederationId,
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

    if let FallbackPolicy::Split {
        funder_split_bps,
        recipient_split_bps,
    } = contract.default_fallback
        && !validate_split_bps(funder_split_bps, recipient_split_bps)
    {
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
    // a fee needs someone to pay it to, otherwise every ruling fails to balance
    if contract.arbiter_fee > Amount::ZERO && contract.arbiter_fee_key.is_empty() {
        return Err(EscrowContractValidationError::MissingArbiterFeeKeys);
    }
    if contract.arbiter_fee_key.len() > 32 {
        return Err(EscrowContractValidationError::InvalidInput);
    }
    Ok(())
}
