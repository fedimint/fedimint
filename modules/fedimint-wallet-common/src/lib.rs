use std::hash::Hasher;

use bitcoin::hashes::hex::ToHex;
use bitcoin::util::psbt::raw::ProprietaryKey;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{Address, Amount, BlockHash, Network, Script, Transaction, Txid};
use config::WalletClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{
    extensible_associated_module_type, plugin_types_trait_impl_common, Feerate, PeerId,
};
use impl_tools::autoimpl;
use miniscript::Descriptor;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::db::UTXOKey;
use crate::keys::CompressedPublicKey;
use crate::txoproof::{PegInProof, PegInProofError};

pub mod config;
pub mod db;
pub mod keys;
pub mod tweakable;
pub mod txoproof;

pub const KIND: ModuleKind = ModuleKind::from_static_str("wallet");
const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(1, 0);

pub const CONFIRMATION_TARGET: u16 = 10;

pub type PartialSig = Vec<u8>;

pub type PegInDescriptor = Descriptor<CompressedPublicKey>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum WalletConsensusItem {
    BlockCount(u32), /* FIXME: use block hash instead, but needs more complicated
                      * * verification logic */
    Feerate(Feerate),
    PegOutSignature(PegOutSignatureItem),
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
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
}

/// A peg-out tx that is ready to be broadcast with a tweak for the change UTXO
#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransaction {
    pub tx: Transaction,
    pub tweak: [u8; 33],
    pub change: bitcoin::Amount,
    pub destination: Script,
    pub fees: PegOutFees,
    pub selected_utxos: Vec<(UTXOKey, SpendableUTXO)>,
    pub peg_out_amount: Amount,
    pub rbf: Option<Rbf>,
}

impl Serialize for PendingTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).unwrap();

        if serializer.is_human_readable() {
            serializer.serialize_str(&bytes.to_hex())
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

/// A PSBT that is awaiting enough signatures from the federation to becoming a
/// `PendingTransaction`
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable)]
pub struct UnsignedTransaction {
    pub psbt: PartiallySignedTransaction,
    pub signatures: Vec<(PeerId, PegOutSignatureItem)>,
    pub change: bitcoin::Amount,
    pub fees: PegOutFees,
    pub destination: Script,
    pub selected_utxos: Vec<(UTXOKey, SpendableUTXO)>,
    pub peg_out_amount: Amount,
    pub rbf: Option<Rbf>,
}

impl Serialize for UnsignedTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).unwrap();

        if serializer.is_human_readable() {
            serializer.serialize_str(&bytes.to_hex())
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
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
    pub recipient: bitcoin::Address,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
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
    const CONSENSUS_VERSION: ModuleConsensusVersion = CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = WalletClientConfig;

    fn decoder() -> Decoder {
        WalletModuleTypes::decoder()
    }
}

extensible_associated_module_type!(WalletInput, WalletInputV0, UnknownWalletInputVariantError);

impl WalletInput {
    pub fn new_v0(peg_in_proof: PegInProof) -> WalletInput {
        WalletInput::V0(WalletInputV0(Box::new(peg_in_proof)))
    }
}

#[autoimpl(Deref, DerefMut using self.0)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletInputV0(pub Box<PegInProof>);

impl std::fmt::Display for WalletInputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Wallet PegIn with Bitcoin TxId {}",
            self.0.outpoint().txid
        )
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
            recipient,
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
                write!(f, "Wallet PegOut {} to {}", pegout.amount, pegout.recipient)
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
        for sig in self.signature.iter() {
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
pub enum WalletCreationError {
    #[error("Connected bitcoind is on wrong network, expected {0}, got {1}")]
    WrongNetwork(Network, Network),
    #[error("Error querying bitcoind: {0}")]
    RpcError(String),
}

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
}

#[derive(Debug, Error, Encodable, Decodable, Hash, Clone, Eq, PartialEq)]
pub enum WalletOutputError {
    #[error("Connected bitcoind is on wrong network, expected {0}, got {1}")]
    WrongNetwork(Network, Network),
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
