use std::hash::Hasher;

use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::sha256;
use bitcoin::util::psbt::raw::ProprietaryKey;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{Amount, BlockHash, Network, Script, Transaction, Txid};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable, UnzipConsensus};
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::module::{ClientModuleGen, CommonModuleGen, ModuleCommon};
use fedimint_core::{
    apply, async_trait_maybe_send, plugin_types_trait_impl_common, Feerate, PeerId,
};
use impl_tools::autoimpl;
use miniscript::Descriptor;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::config::WalletClientConfig;
use crate::db::UTXOKey;
use crate::keys::CompressedPublicKey;
use crate::txoproof::{PegInProof, PegInProofError};

pub mod config;
pub mod db;
pub mod keys;
pub mod tweakable;
pub mod txoproof;

const KIND: ModuleKind = ModuleKind::from_static_str("wallet");

pub const CONFIRMATION_TARGET: u16 = 10;

pub type PartialSig = Vec<u8>;

pub type PegInDescriptor = Descriptor<CompressedPublicKey>;

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, UnzipConsensus, Encodable, Decodable,
)]
pub enum WalletConsensusItem {
    RoundConsensus(RoundConsensusItem),
    PegOutSignature(PegOutSignatureItem),
}

impl std::fmt::Display for WalletConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletConsensusItem::RoundConsensus(rc) => {
                write!(f, "Wallet Block Height {}", rc.block_height)
            }
            WalletConsensusItem::PegOutSignature(sig) => {
                write!(f, "Wallet PegOut signature for Bitcoin TxId {}", sig.txid)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct RoundConsensusItem {
    pub block_height: u32, /* FIXME: use block hash instead, but needs more complicated
                            * verification logic */
    pub fee_rate: Feerate,
    pub randomness: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct PegOutSignatureItem {
    pub txid: Txid,
    pub signature: Vec<secp256k1::ecdsa::Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct RoundConsensus {
    pub block_height: u32,
    pub fee_rate: Feerate,
    pub randomness_beacon: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpendableUTXO {
    pub tweak: [u8; 32],
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
}

/// A peg-out tx that is ready to be broadcast with a tweak for the change UTXO
#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransaction {
    pub tx: Transaction,
    pub tweak: [u8; 32],
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
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

/// Contains the Bitcoin transaction id of the transaction created by the
/// withdraw request
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletOutputOutcome(pub bitcoin::Txid);

impl std::fmt::Display for WalletOutputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet PegOut Bitcoin TxId {}", self.0)
    }
}

#[derive(Debug)]
pub struct WalletCommonGen;

impl CommonModuleGen for WalletCommonGen {
    const KIND: ModuleKind = KIND;
    fn decoder() -> Decoder {
        WalletModuleTypes::decoder()
    }

    fn hash_client_module(config: serde_json::Value) -> anyhow::Result<sha256::Hash> {
        serde_json::from_value::<WalletClientConfig>(config)?.consensus_hash()
    }
}

#[derive(Debug)]
pub struct WalletClientGen;

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for WalletClientGen {
    type Common = WalletCommonGen;
}

#[autoimpl(Deref, DerefMut using self.0)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletInput(pub Box<PegInProof>);

impl std::fmt::Display for WalletInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Wallet PegIn with Bitcoin TxId {}",
            self.0.outpoint().txid
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum WalletOutput {
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

impl WalletOutput {
    pub fn amount(&self) -> Amount {
        match self {
            WalletOutput::PegOut(pegout) => pegout.amount + pegout.fees.amount(),
            WalletOutput::Rbf(rbf) => rbf.fees.amount(),
        }
    }
}

impl std::fmt::Display for WalletOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletOutput::PegOut(pegout) => {
                write!(f, "Wallet PegOut {} to {}", pegout.amount, pegout.recipient)
            }
            WalletOutput::Rbf(rbf) => write!(f, "Wallet RBF {:?} to {}", rbf.fees, rbf.txid),
        }
    }
}

pub struct WalletModuleTypes;

impl ModuleCommon for WalletModuleTypes {
    type Input = WalletInput;
    type Output = WalletOutput;
    type OutputOutcome = WalletOutputOutcome;
    type ConsensusItem = WalletConsensusItem;
}

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
    WalletInput,
    WalletOutput,
    WalletOutputOutcome,
    WalletConsensusItem
);

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Connected bitcoind is on wrong network, expected {0}, got {1}")]
    WrongNetwork(Network, Network),
    #[error("Error querying bitcoind: {0}")]
    RpcError(#[from] anyhow::Error),
    #[error("Unknown bitcoin network: {0}")]
    UnknownNetwork(String),
    #[error("Unknown block hash in peg-in proof: {0}")]
    UnknownPegInProofBlock(BlockHash),
    #[error("Invalid peg-in proof: {0}")]
    PegInProofError(#[from] PegInProofError),
    #[error("The peg-in was already claimed")]
    PegInAlreadyClaimed,
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

// FIXME: make FakeFed not require Eq
/// **WARNING**: this is only intended to be used for testing
impl PartialEq for WalletError {
    fn eq(&self, other: &Self) -> bool {
        format!("{self:?}") == format!("{other:?}")
    }
}

/// **WARNING**: this is only intended to be used for testing
impl Eq for WalletError {}
