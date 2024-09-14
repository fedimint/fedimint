#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use core::panic;
use std::collections::BTreeMap;
use std::time::Duration;

use bitcoin::hashes::{Hash, hash160, sha256};
use bitcoin::key::TapTweak;
use bitcoin::{Address, PubkeyHash, ScriptBuf, ScriptHash, Txid, WPubkeyHash, WScriptHash};
use config::WalletClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{
    NumPeersExt, PeerId, extensible_associated_module_type, plugin_types_trait_impl_common,
};
use miniscript::descriptor::Wsh;
use secp256k1::ecdsa::Signature;
use secp256k1::{PublicKey, Scalar, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

pub mod config;
pub mod endpoint_constants;

pub const KIND: ModuleKind = ModuleKind::from_static_str("walletv2");

pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(1, 0);

/// Returns a sleep duration of 1 second in test environments or 60 seconds in
/// production. Used for polling intervals where faster feedback is needed
/// during testing.
pub fn sleep_duration() -> Duration {
    if fedimint_core::envs::is_running_in_test_env() {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(60)
    }
}

pub fn descriptor(
    pks: &BTreeMap<PeerId, PublicKey>,
    tweak: Option<&sha256::Hash>,
) -> Wsh<PublicKey> {
    Wsh::new_sortedmulti(
        pks.to_num_peers().threshold(),
        pks.values()
            .map(|pk| match tweak {
                Some(tweak) => tweak_public_key(pk, tweak),
                None => *pk,
            })
            .collect::<Vec<PublicKey>>(),
    )
    .expect("Failed to construct Descriptor")
}

pub fn tweak_public_key(pk: &PublicKey, tweak: &sha256::Hash) -> PublicKey {
    pk.add_exp_tweak(
        secp256k1::SECP256K1,
        &Scalar::from_be_bytes(tweak.to_byte_array()).expect("Hash is within field order"),
    )
    .expect("Failed to tweak bitcoin public key")
}

/// Returns true if the script pubkey is a valid deposit address for the
/// federation. This uses a probabilistic filter - only ~1/65536 of P2WSH
/// scripts pass.
pub fn is_valid_script(script_pubkey: &ScriptBuf, pks_hash: &sha256::Hash) -> bool {
    (script_pubkey, pks_hash)
        .consensus_hash::<sha256::Hash>()
        .to_byte_array()
        .iter()
        .take(2)
        .all(|b| *b == 0)
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub enum DestinationScript {
    P2PKH(hash160::Hash),
    P2SH(hash160::Hash),
    P2WPKH(hash160::Hash),
    P2WSH(sha256::Hash),
    P2TR(XOnlyPublicKey),
}

impl DestinationScript {
    pub fn from_address(address: &Address) -> Self {
        if let Some(hash) = address.pubkey_hash() {
            return DestinationScript::P2PKH(hash.to_raw_hash());
        }

        if let Some(hash) = address.script_hash() {
            return DestinationScript::P2PKH(hash.to_raw_hash());
        }

        if let Some(program) = address.witness_program() {
            if program.is_p2wpkh() {
                return DestinationScript::P2WPKH(
                    hash160::Hash::from_slice(program.program().as_bytes())
                        .expect("Witness program is 20 bytes"),
                );
            }

            if program.is_p2wsh() {
                return DestinationScript::P2WSH(
                    sha256::Hash::from_slice(program.program().as_bytes())
                        .expect("Witness program is 32 bytes"),
                );
            }

            if program.is_p2tr() {
                return DestinationScript::P2TR(
                    XOnlyPublicKey::from_slice(program.program().as_bytes())
                        .expect("Witness program is 32 bytes"),
                );
            }
        }

        panic!("Failed to obtain Destination from address");
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        match self {
            Self::P2PKH(hash) => ScriptBuf::new_p2pkh(&PubkeyHash::from_raw_hash(*hash)),
            Self::P2SH(hash) => ScriptBuf::new_p2sh(&ScriptHash::from_raw_hash(*hash)),
            Self::P2WPKH(hash) => ScriptBuf::new_p2wpkh(&WPubkeyHash::from_raw_hash(*hash)),
            Self::P2WSH(hash) => ScriptBuf::new_p2wsh(&WScriptHash::from_raw_hash(*hash)),
            Self::P2TR(pk) => ScriptBuf::new_p2tr_tweaked(pk.dangerous_assume_tweaked()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct FederationWallet {
    pub value: bitcoin::Amount,
    pub txid: bitcoin::Txid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub index: u64,
    pub txid: bitcoin::Txid,
    pub input: bitcoin::Amount,
    pub output: bitcoin::Amount,
    pub fee: bitcoin::Amount,
    pub vbytes: u64,
    pub feerate: u64,
    pub created: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositRange {
    pub deposits: Vec<bitcoin::TxOut>,
    pub spent: Vec<u64>,
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

pub struct WalletModuleTypes;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum WalletConsensusItem {
    BlockCount(u64),
    Feerate(Option<u64>),
    Signatures(Txid, Vec<Signature>),
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
                write!(f, "Wallet Feerate Vote {feerate:?}")
            }
            WalletConsensusItem::Signatures(..) => {
                write!(f, "Wallet Signatures")
            }
            WalletConsensusItem::Default { variant, .. } => {
                write!(f, "Unknown Wallet CI variant={variant}")
            }
        }
    }
}

extensible_associated_module_type!(WalletInput, WalletInputV0, UnknownWalletInputVariantError);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletInputV0 {
    pub deposit_index: u64,
    pub tweak: PublicKey,
    pub fee: bitcoin::Amount,
}

impl std::fmt::Display for WalletInputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet PegIn for deposit index {}", self.deposit_index)
    }
}

extensible_associated_module_type!(
    WalletOutput,
    WalletOutputV0,
    UnknownWalletOutputVariantError
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletOutputV0 {
    pub destination: DestinationScript,
    pub value: bitcoin::Amount,
    pub fee: bitcoin::Amount,
}

impl std::fmt::Display for WalletOutputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet PegOut {}", self.value,)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct WalletOutputOutcome;

impl std::fmt::Display for WalletOutputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wallet Output Outcome")
    }
}

#[derive(Debug, Error, Encodable, Decodable, Hash, Clone, Eq, PartialEq)]
pub enum WalletInputError {
    #[error("The wallet input version is not supported by this federation")]
    UnknownInputVariant(#[from] UnknownWalletInputVariantError),
    #[error("The deposit has already been claimed")]
    DepositAlreadySpent,
    #[error("Unknown deposit index")]
    UnknownDepositIndex,
    #[error("The tweak does not match the deposit script")]
    WrongTweak,
    #[error("No up to date feerate is available at the moment. Please try again later.")]
    NoConsensusFeerateAvailable,
    #[error("The total transaction fee is to low. Please construct an new transaction.")]
    InsufficientTotalFee,
    #[error("Constructing the pegin transaction caused and arithmetic overflow")]
    ArithmeticOverflow,
}

#[derive(Debug, Error, Encodable, Decodable, Hash, Clone, Eq, PartialEq)]
pub enum WalletOutputError {
    #[error("The wallet output version is not supported by this federation")]
    UnknownOutputVariant(#[from] UnknownWalletOutputVariantError),
    #[error("Connected bitcoind is on wrong network.")]
    UnderDustLimit,
    #[error("The federation does not have any funds yet")]
    NoFederationUTXO,
    #[error("No up to date feerate is available at the moment. Please try again later.")]
    NoConsensusFeerateAvailable,
    #[error("The total transaction fee is to low. Please construct an new transaction.")]
    InsufficicentTotalFee,
    #[error("Constructing the pegout transaction caused and arithmetic overflow")]
    ArithmeticOverflow,
}
