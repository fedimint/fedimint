#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::return_self_not_must_use)]

use std::hash::Hasher;

use bitcoin::address::NetworkUnchecked;
use bitcoin::psbt::raw::ProprietaryKey;
use bitcoin::{Address, Amount, BlockHash, TxOut, Txid, secp256k1};
use config::WalletClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{Feerate, extensible_associated_module_type, plugin_types_trait_impl_common};
use impl_tools::autoimpl;
use miniscript::Descriptor;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::keys::CompressedPublicKey;
use crate::txoproof::{PegInProof, PegInProofError};

pub mod config;
pub mod endpoint_constants;
pub mod envs;
pub mod keys;
pub mod tweakable;
pub mod txoproof;

pub const KIND: ModuleKind = ModuleKind::from_static_str("wallet");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(2, 2);

/// Module consensus version that introduced support for processing Bitcoin
/// transactions that exceed the `ALEPH_BFT_UNIT_BYTE_LIMIT`.
pub const SAFE_DEPOSIT_MODULE_CONSENSUS_VERSION: ModuleConsensusVersion =
    ModuleConsensusVersion::new(2, 2);

/// To further mitigate the risk of a peg-out transaction getting stuck in the
/// mempool, we multiply the feerate estimate returned from the backend by this
/// value.
pub const FEERATE_MULTIPLIER_DEFAULT: f64 = 2.0;

pub type PartialSig = Vec<u8>;

pub type PegInDescriptor = Descriptor<CompressedPublicKey>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum WalletConsensusItem {
    BlockCount(u32), /* FIXME: use block hash instead, but needs more complicated
                      * * verification logic */
    Feerate(Feerate),
    PegOutSignature(PegOutSignatureItem),
    ModuleConsensusVersion(ModuleConsensusVersion),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl std::fmt::Display for WalletConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletConsensusItem::BlockCount(count) => {
                write!(f, "Wallet Block Count {count}")
            }
            WalletConsensusItem::Feerate(feerate) => {
                write!(
                    f,
                    "Wallet Feerate with sats per kvb {}",
                    feerate.sats_per_kvb
                )
            }
            WalletConsensusItem::PegOutSignature(sig) => {
                write!(f, "Wallet PegOut signature for Bitcoin TxId {}", sig.txid)
            }
            WalletConsensusItem::ModuleConsensusVersion(version) => {
                write!(
                    f,
                    "Wallet Consensus Version {}.{}",
                    version.major, version.minor
                )
            }
            WalletConsensusItem::Default { variant, .. } => {
                write!(f, "Unknown Wallet CI variant={variant}")
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct PegOutSignatureItem {
    pub txid: Txid,
    pub signature: Vec<secp256k1::ecdsa::Signature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpendableUTXO {
    #[serde(with = "::fedimint_core::encoding::as_hex")]
    pub tweak: [u8; 33],
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
}

/// A transaction output, either unspent or consumed
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct TxOutputSummary {
    pub outpoint: bitcoin::OutPoint,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
}

/// Summary of the coins within the wallet.
///
/// Coins within the wallet go from spendable, to consumed in a transaction that
/// does not have threshold signatures (unsigned), to threshold signed and
/// unconfirmed on-chain (unconfirmed).
///
/// This summary provides the most granular view possible of coins in the
/// wallet.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletSummary {
    /// All UTXOs available as inputs for transactions
    pub spendable_utxos: Vec<TxOutputSummary>,
    /// Transaction outputs consumed in peg-out transactions that have not
    /// reached threshold signatures
    pub unsigned_peg_out_txos: Vec<TxOutputSummary>,
    /// Change UTXOs created from peg-out transactions that have not reached
    /// threshold signatures
    pub unsigned_change_utxos: Vec<TxOutputSummary>,
    /// Transaction outputs consumed in peg-out transactions that have reached
    /// threshold signatures waiting for finality delay confirmations
    pub unconfirmed_peg_out_txos: Vec<TxOutputSummary>,
    /// Change UTXOs created from peg-out transactions that have reached
    /// threshold signatures waiting for finality delay confirmations
    pub unconfirmed_change_utxos: Vec<TxOutputSummary>,
}

impl WalletSummary {
    fn sum<'a>(txos: impl Iterator<Item = &'a TxOutputSummary>) -> Amount {
        txos.fold(Amount::ZERO, |acc, txo| txo.amount + acc)
    }

    /// Total amount of all spendable UTXOs
    pub fn total_spendable_balance(&self) -> Amount {
        WalletSummary::sum(self.spendable_utxos.iter())
    }

    /// Total amount of all transaction outputs from peg-out transactions that
    /// have not reached threshold signatures
    pub fn total_unsigned_peg_out_balance(&self) -> Amount {
        WalletSummary::sum(self.unsigned_peg_out_txos.iter())
    }

    /// Total amount of all change UTXOs from peg-out transactions that have not
    /// reached threshold signatures
    pub fn total_unsigned_change_balance(&self) -> Amount {
        WalletSummary::sum(self.unsigned_change_utxos.iter())
    }

    /// Total amount of all transaction outputs from peg-out transactions that
    /// have reached threshold signatures waiting for finality delay
    /// confirmations
    pub fn total_unconfirmed_peg_out_balance(&self) -> Amount {
        WalletSummary::sum(self.unconfirmed_peg_out_txos.iter())
    }

    /// Total amount of all change UTXOs from peg-out transactions that have
    /// reached threshold signatures waiting for finality delay confirmations
    pub fn total_unconfirmed_change_balance(&self) -> Amount {
        WalletSummary::sum(self.unconfirmed_change_utxos.iter())
    }

    /// Total amount of all transaction outputs from peg-out transactions that
    /// are either waiting for threshold signatures or confirmations. This is
    /// the total in-flight amount leaving the wallet.
    pub fn total_pending_peg_out_balance(&self) -> Amount {
        self.total_unsigned_peg_out_balance() + self.total_unconfirmed_peg_out_balance()
    }

    /// Total amount of all change UTXOs from peg-out transactions that are
    /// either waiting for threshold signatures or confirmations. This is the
    /// total in-flight amount that will become spendable by the wallet.
    pub fn total_pending_change_balance(&self) -> Amount {
        self.total_unsigned_change_balance() + self.total_unconfirmed_change_balance()
    }

    /// Total amount of immediately spendable UTXOs and pending change UTXOs.
    /// This is the spendable balance once all transactions confirm.
    pub fn total_owned_balance(&self) -> Amount {
        self.total_spendable_balance() + self.total_pending_change_balance()
    }

    /// All transaction outputs from peg-out transactions that are either
    /// waiting for threshold signatures or confirmations. These are all the
    /// in-flight coins leaving the wallet.
    pub fn pending_peg_out_txos(&self) -> Vec<TxOutputSummary> {
        self.unsigned_peg_out_txos
            .clone()
            .into_iter()
            .chain(self.unconfirmed_peg_out_txos.clone())
            .collect()
    }

    /// All change UTXOs from peg-out transactions that are either waiting for
    /// threshold signatures or confirmations. These are all the in-flight coins
    /// that will become spendable by the wallet.
    pub fn pending_change_utxos(&self) -> Vec<TxOutputSummary> {
        self.unsigned_change_utxos
            .clone()
            .into_iter()
            .chain(self.unconfirmed_change_utxos.clone())
            .collect()
    }
}

/// Recovery data for slice-based client recovery
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum RecoveryItem {
    /// A peg-in input was claimed
    Input {
        /// The Bitcoin outpoint that was claimed
        outpoint: bitcoin::OutPoint,
        /// The `script_pubkey` of the peg-in address (tweaked descriptor)
        script: bitcoin::ScriptBuf,
    },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PegOutFees {
    pub fee_rate: Feerate,
    pub total_weight: u64,
}

impl PegOutFees {
    pub fn new(sats_per_kvb: u64, total_weight: u64) -> Self {
        PegOutFees {
            fee_rate: Feerate { sats_per_kvb },
            total_weight,
        }
    }

    pub fn amount(&self) -> Amount {
        self.fee_rate.calculate_fee(self.total_weight)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PegOut {
    pub recipient: Address<NetworkUnchecked>,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
    pub fees: PegOutFees,
}

extensible_associated_module_type!(
    WalletOutputOutcome,
    WalletOutputOutcomeV0,
    UnknownWalletOutputOutcomeVariantError
);

impl WalletOutputOutcome {
    pub fn new_v0(txid: bitcoin::Txid) -> WalletOutputOutcome {
        WalletOutputOutcome::V0(WalletOutputOutcomeV0(txid))
    }
}

/// Contains the Bitcoin transaction id of the transaction created by the
/// withdraw request
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletOutputOutcomeV0(pub bitcoin::Txid);

impl std::fmt::Display for WalletOutputOutcomeV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet PegOut Bitcoin TxId {}", self.0)
    }
}

#[derive(Debug)]
pub struct WalletCommonInit;

impl CommonModuleInit for WalletCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = WalletClientConfig;

    fn decoder() -> Decoder {
        WalletModuleTypes::decoder()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum WalletInput {
    V0(WalletInputV0),
    V1(WalletInputV1),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl WalletInput {
    pub fn maybe_v0_ref(&self) -> Option<&WalletInputV0> {
        match self {
            WalletInput::V0(v0) => Some(v0),
            _ => None,
        }
    }
}

#[derive(
    Debug,
    thiserror::Error,
    Clone,
    Eq,
    PartialEq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
    fedimint_core::encoding::Encodable,
    fedimint_core::encoding::Decodable,
)]
#[error("Unknown {} variant {variant}", stringify!($name))]
pub struct UnknownWalletInputVariantError {
    pub variant: u64,
}

impl std::fmt::Display for WalletInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            WalletInput::V0(inner) => std::fmt::Display::fmt(&inner, f),
            WalletInput::V1(inner) => std::fmt::Display::fmt(&inner, f),
            WalletInput::Default { variant, .. } => {
                write!(f, "Unknown variant (variant={variant})")
            }
        }
    }
}

impl WalletInput {
    pub fn new_v0(peg_in_proof: PegInProof) -> WalletInput {
        WalletInput::V0(WalletInputV0(Box::new(peg_in_proof)))
    }

    pub fn new_v1(peg_in_proof: &PegInProof) -> WalletInput {
        WalletInput::V1(WalletInputV1 {
            outpoint: peg_in_proof.outpoint(),
            tweak_key: peg_in_proof.tweak_key(),
            tx_out: peg_in_proof.tx_output(),
        })
    }
}

#[autoimpl(Deref, DerefMut using self.0)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletInputV0(pub Box<PegInProof>);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletInputV1 {
    pub outpoint: bitcoin::OutPoint,
    pub tweak_key: secp256k1::PublicKey,
    pub tx_out: TxOut,
}

impl std::fmt::Display for WalletInputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Wallet PegIn with Bitcoin TxId {}",
            self.0.outpoint().txid
        )
    }
}

impl std::fmt::Display for WalletInputV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet PegIn V1 with TxId {}", self.outpoint.txid)
    }
}

extensible_associated_module_type!(
    WalletOutput,
    WalletOutputV0,
    UnknownWalletOutputVariantError
);

impl WalletOutput {
    pub fn new_v0_peg_out(
        recipient: Address,
        amount: bitcoin::Amount,
        fees: PegOutFees,
    ) -> WalletOutput {
        WalletOutput::V0(WalletOutputV0::PegOut(PegOut {
            recipient: recipient.into_unchecked(),
            amount,
            fees,
        }))
    }
    pub fn new_v0_rbf(fees: PegOutFees, txid: Txid) -> WalletOutput {
        WalletOutput::V0(WalletOutputV0::Rbf(Rbf { fees, txid }))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum WalletOutputV0 {
    PegOut(PegOut),
    Rbf(Rbf),
}

/// Allows a user to bump the fees of a `PendingTransaction`
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Rbf {
    /// Fees expressed as an increase over existing peg-out fees
    pub fees: PegOutFees,
    /// Bitcoin tx id to bump the fees for
    pub txid: Txid,
}

impl WalletOutputV0 {
    pub fn amount(&self) -> Amount {
        match self {
            WalletOutputV0::PegOut(pegout) => pegout.amount + pegout.fees.amount(),
            WalletOutputV0::Rbf(rbf) => rbf.fees.amount(),
        }
    }
}

impl std::fmt::Display for WalletOutputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletOutputV0::PegOut(pegout) => {
                write!(
                    f,
                    "Wallet PegOut {} to {}",
                    pegout.amount,
                    pegout.recipient.clone().assume_checked()
                )
            }
            WalletOutputV0::Rbf(rbf) => write!(f, "Wallet RBF {:?} to {}", rbf.fees, rbf.txid),
        }
    }
}

pub struct WalletModuleTypes;

pub fn proprietary_tweak_key() -> ProprietaryKey {
    ProprietaryKey {
        prefix: b"fedimint".to_vec(),
        subtype: 0x00,
        key: vec![],
    }
}

impl std::hash::Hash for PegOutSignatureItem {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.txid.hash(state);
        for sig in &self.signature {
            sig.serialize_der().hash(state);
        }
    }
}

impl PartialEq for PegOutSignatureItem {
    fn eq(&self, other: &PegOutSignatureItem) -> bool {
        self.txid == other.txid && self.signature == other.signature
    }
}

impl Eq for PegOutSignatureItem {}

plugin_types_trait_impl_common!(
    KIND,
    WalletModuleTypes,
    WalletClientConfig,
    WalletInput,
    WalletOutput,
    WalletOutputOutcome,
    WalletConsensusItem,
    WalletInputError,
    WalletOutputError
);

#[derive(Debug, Error, Encodable, Decodable, Hash, Clone, Eq, PartialEq)]
pub enum WalletInputError {
    #[error("Unknown block hash in peg-in proof: {0}")]
    UnknownPegInProofBlock(BlockHash),
    #[error("Invalid peg-in proof: {0}")]
    PegInProofError(#[from] PegInProofError),
    #[error("The peg-in was already claimed")]
    PegInAlreadyClaimed,
    #[error("The wallet input version is not supported by this federation")]
    UnknownInputVariant(#[from] UnknownWalletInputVariantError),
    #[error("Unknown UTXO")]
    UnknownUTXO,
    #[error("Wrong output script")]
    WrongOutputScript,
    #[error("Wrong tx out")]
    WrongTxOut,
}

#[derive(Debug, Error, Encodable, Decodable, Hash, Clone, Eq, PartialEq)]
pub enum WalletOutputError {
    #[error("Connected bitcoind is on wrong network, expected {0}, got {1}")]
    WrongNetwork(NetworkLegacyEncodingWrapper, NetworkLegacyEncodingWrapper),
    #[error("Peg-out fee rate {0:?} is set below consensus {1:?}")]
    PegOutFeeBelowConsensus(Feerate, Feerate),
    #[error("Not enough SpendableUTXO")]
    NotEnoughSpendableUTXO,
    #[error("Peg out amount was under the dust limit")]
    PegOutUnderDustLimit,
    #[error("RBF transaction id not found")]
    RbfTransactionIdNotFound,
    #[error("Peg-out fee weight {0} doesn't match actual weight {1}")]
    TxWeightIncorrect(u64, u64),
    #[error("Peg-out fee rate is below min relay fee")]
    BelowMinRelayFee,
    #[error("The wallet output version is not supported by this federation")]
    UnknownOutputVariant(#[from] UnknownWalletOutputVariantError),
}

// For backwards-compatibility with old clients, we use an UnknownOutputVariant
// error when a client attempts a deprecated RBF withdrawal.
// see: https://github.com/fedimint/fedimint/issues/5453
pub const DEPRECATED_RBF_ERROR: WalletOutputError =
    WalletOutputError::UnknownOutputVariant(UnknownWalletOutputVariantError { variant: 1 });

#[derive(Debug, Error)]
pub enum ProcessPegOutSigError {
    #[error("No unsigned transaction with id {0} exists")]
    UnknownTransaction(Txid),
    #[error("Expected {0} signatures, got {1}")]
    WrongSignatureCount(usize, usize),
    #[error("Bad Sighash")]
    SighashError,
    #[error("Malformed signature: {0}")]
    MalformedSignature(secp256k1::Error),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Duplicate signature")]
    DuplicateSignature,
    #[error("Missing change tweak")]
    MissingOrMalformedChangeTweak,
    #[error("Error finalizing PSBT {0:?}")]
    ErrorFinalizingPsbt(Vec<miniscript::psbt::Error>),
}
