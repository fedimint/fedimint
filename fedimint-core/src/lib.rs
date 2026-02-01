#![deny(clippy::pedantic, clippy::nursery)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::future_not_send)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::transmute_ptr_to_ptr)]
#![allow(clippy::unsafe_derive_deserialize)]

//! Fedimint Core library
//!
//! `fedimint-core` contains commonly used types, utilities and primitives,
//! shared between both client and server code.
//!
//! Things that are server-side only typically live in `fedimint-server`, and
//! client-side only in `fedimint-client`.
//!
//! ### Wasm support
//!
//! All code in `fedimint-core` needs to compile on Wasm, and `fedimint-core`
//! includes helpers and wrappers around non-wasm-safe utitlies.
//!
//! In particular:
//!
//! * [`fedimint_core::task`] for task spawning and control
//! * [`fedimint_core::time`] for time-related operations

extern crate self as fedimint_core;

use std::fmt::{self, Debug};
use std::io::Error;
use std::ops::{self, Range};
use std::str::FromStr;

pub use amount::*;
/// Mostly re-exported for [`Decodable`] macros.
pub use anyhow;
use bitcoin::address::NetworkUnchecked;
pub use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::{Address, Network};
use envs::BitcoinRpcConfig;
use lightning::util::ser::Writeable;
use lightning_types::features::Bolt11InvoiceFeatures;
pub use macro_rules_attribute::apply;
pub use peer_id::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
pub use tiered::Tiered;
pub use tiered_multi::*;
use util::SafeUrl;
pub use {bitcoin, hex, secp256k1};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

/// Admin (guardian) client types
pub mod admin_client;
/// Bitcoin amount types
mod amount;
/// Federation-stored client backups
pub mod backup;
/// Legacy serde encoding for `bls12_381`
pub mod bls12_381_serde;
/// Federation configuration
pub mod config;
/// Fundamental types
pub mod core;
/// Database handling
pub mod db;
/// Consensus encoding
pub mod encoding;
pub mod endpoint_constants;
/// Common environment variables
pub mod envs;
pub mod epoch;
/// Formatting helpers
pub mod fmt_utils;
/// Federation invite code
pub mod invite_code;
pub mod log;
/// Common macros
#[macro_use]
pub mod macros;
/// Base 32 encoding
pub mod base32;
/// Extendable module sysystem
pub mod module;
/// Peer networking
pub mod net;
/// `PeerId` type
mod peer_id;
/// Runtime (wasm32 vs native) differences handling
pub mod runtime;
/// Rustls support
pub mod rustls;
/// Peer setup code for setup ceremony
pub mod setup_code;
/// Task handling, including wasm safe logic
pub mod task;
/// Types handling per-denomination values
pub mod tiered;
/// Types handling multiple per-denomination values
pub mod tiered_multi;
/// Time handling, wasm safe functionality
pub mod time;
/// Timing helpers
pub mod timing;
/// Fedimint transaction (inpus + outputs + signature) types
pub mod transaction;
/// Peg-in txo proofs
pub mod txoproof;
/// General purpose utilities
pub mod util;
/// Version
pub mod version;

/// Atomic BFT unit containing consensus items
pub mod session_outcome;

// It's necessary to wrap `hash_newtype!` in a module because the generated code
// references a module called "core", but we export a conflicting module in this
// file.
mod txid {
    use bitcoin::hashes::hash_newtype;
    use bitcoin::hashes::sha256::Hash as Sha256;

    hash_newtype!(
        /// A transaction id for peg-ins, peg-outs and reissuances
        pub struct TransactionId(Sha256);
    );
}
pub use txid::TransactionId;

/// Bitcoin chain identifier
///
/// This is a newtype wrapper around [`bitcoin::BlockHash`] representing the
/// block hash at height 1, which uniquely identifies a Bitcoin chain (mainnet,
/// testnet, signet, regtest, or custom networks), unlike genesis block hash
/// which is often the same for same types of networks (e.g. mutinynet vs
/// signet4).
///
/// Using a distinct type instead of raw `BlockHash` provides type safety and
/// makes the intent clearer when passing chain identifiers through APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encodable, Decodable)]
pub struct ChainId(pub bitcoin::BlockHash);

impl ChainId {
    /// Create a new `ChainId` from a `BlockHash`
    pub fn new(block_hash: bitcoin::BlockHash) -> Self {
        Self(block_hash)
    }

    /// Get the inner `BlockHash`
    pub fn block_hash(&self) -> bitcoin::BlockHash {
        self.0
    }
}

impl From<bitcoin::BlockHash> for ChainId {
    fn from(block_hash: bitcoin::BlockHash) -> Self {
        Self(block_hash)
    }
}

impl From<ChainId> for bitcoin::BlockHash {
    fn from(chain_id: ChainId) -> Self {
        chain_id.0
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ChainId {
    type Err = bitcoin::hashes::hex::HexToArrayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bitcoin::BlockHash::from_str(s).map(Self)
    }
}

impl Serialize for ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        bitcoin::BlockHash::deserialize(deserializer).map(Self)
    }
}

/// Amount of bitcoin to send, or `All` to send all available funds
#[derive(Debug, Eq, PartialEq, Copy, Hash, Clone)]
pub enum BitcoinAmountOrAll {
    All,
    Amount(bitcoin::Amount),
}

impl std::fmt::Display for BitcoinAmountOrAll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Amount(amount) => write!(f, "{amount}"),
        }
    }
}

impl FromStr for BitcoinAmountOrAll {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("all") {
            Ok(Self::All)
        } else {
            let amount = Amount::from_str(s)?;
            Ok(Self::Amount(amount.try_into()?))
        }
    }
}

// Custom serde to handle both "all" and numbers/strings
impl<'de> Deserialize<'de> for BitcoinAmountOrAll {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = BitcoinAmountOrAll;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a bitcoin amount as number or 'all'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v.eq_ignore_ascii_case("all") {
                    Ok(BitcoinAmountOrAll::All)
                } else {
                    let sat: u64 = v.parse().map_err(E::custom)?;
                    Ok(BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(sat)))
                }
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(v)))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v < 0 {
                    return Err(E::custom("amount cannot be negative"));
                }
                Ok(BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(
                    v as u64,
                )))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl Serialize for BitcoinAmountOrAll {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::All => serializer.serialize_str("all"),
            Self::Amount(a) => serializer.serialize_u64(a.to_sat()),
        }
    }
}

/// `InPoint` represents a globally unique input in a transaction
///
/// Hence, a transaction ID and the input index is required.
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    Encodable,
    Decodable,
)]
pub struct InPoint {
    /// The referenced transaction ID
    pub txid: TransactionId,
    /// As a transaction may have multiple inputs, this refers to the index of
    /// the input in a transaction
    pub in_idx: u64,
}

impl std::fmt::Display for InPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.in_idx)
    }
}

/// `OutPoint` represents a globally unique output in a transaction
///
/// Hence, a transaction ID and the output index is required.
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    Encodable,
    Decodable,
)]
pub struct OutPoint {
    /// The referenced transaction ID
    pub txid: TransactionId,
    /// As a transaction may have multiple outputs, this refers to the index of
    /// the output in a transaction
    pub out_idx: u64,
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.out_idx)
    }
}

/// A contiguous range of input/output indexes
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct IdxRange {
    start: u64,
    end: u64,
}

impl IdxRange {
    pub fn new_single(start: u64) -> Option<Self> {
        start.checked_add(1).map(|end| Self { start, end })
    }

    pub fn start(self) -> u64 {
        self.start
    }

    pub fn count(self) -> usize {
        self.into_iter().count()
    }

    pub fn from_inclusive(range: ops::RangeInclusive<u64>) -> Option<Self> {
        range.end().checked_add(1).map(|end| Self {
            start: *range.start(),
            end,
        })
    }
}

impl From<Range<u64>> for IdxRange {
    fn from(Range { start, end }: Range<u64>) -> Self {
        Self { start, end }
    }
}

impl IntoIterator for IdxRange {
    type Item = u64;
    type IntoIter = ops::Range<u64>;

    fn into_iter(self) -> Self::IntoIter {
        ops::Range {
            start: self.start,
            end: self.end,
        }
    }
}

/// Represents a range of output indices for a single transaction
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct OutPointRange {
    pub txid: TransactionId,
    idx_range: IdxRange,
}

impl OutPointRange {
    pub fn new(txid: TransactionId, idx_range: IdxRange) -> Self {
        Self { txid, idx_range }
    }

    pub fn new_single(txid: TransactionId, idx: u64) -> Option<Self> {
        IdxRange::new_single(idx).map(|idx_range| Self { txid, idx_range })
    }

    pub fn start_idx(self) -> u64 {
        self.idx_range.start()
    }

    pub fn out_idx_iter(self) -> impl Iterator<Item = u64> {
        self.idx_range.into_iter()
    }

    pub fn count(self) -> usize {
        self.idx_range.count()
    }

    pub fn txid(&self) -> TransactionId {
        self.txid
    }
}

impl IntoIterator for OutPointRange {
    type Item = OutPoint;
    type IntoIter = OutPointRangeIter;

    fn into_iter(self) -> Self::IntoIter {
        OutPointRangeIter {
            txid: self.txid,
            inner: self.idx_range.into_iter(),
        }
    }
}

pub struct OutPointRangeIter {
    txid: TransactionId,
    inner: ops::Range<u64>,
}

impl Iterator for OutPointRangeIter {
    type Item = OutPoint;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|idx| OutPoint {
            txid: self.txid,
            out_idx: idx,
        })
    }
}

impl Encodable for TransactionId {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        let bytes = &self[..];
        writer.write_all(bytes)?;
        Ok(())
    }
}

impl Decodable for TransactionId {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(Self::from_byte_array(bytes))
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Ord,
    PartialOrd,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct Feerate {
    pub sats_per_kvb: u64,
}

impl fmt::Display for Feerate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}sat/kvb", self.sats_per_kvb))
    }
}

impl Feerate {
    pub fn calculate_fee(&self, weight: u64) -> bitcoin::Amount {
        let sats = weight_to_vbytes(weight) * self.sats_per_kvb / 1000;
        bitcoin::Amount::from_sat(sats)
    }
}

const WITNESS_SCALE_FACTOR: u64 = bitcoin::constants::WITNESS_SCALE_FACTOR as u64;

/// Converts weight to virtual bytes, defined in [BIP-141] as weight / 4
/// (rounded up to the next integer).
///
/// [BIP-141]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-size-calculations
pub fn weight_to_vbytes(weight: u64) -> u64 {
    weight.div_ceil(WITNESS_SCALE_FACTOR)
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Mismatching outcome variant: expected {0}, got {1}")]
    MismatchingVariant(&'static str, &'static str),
}

// Encode features for a bolt11 invoice without encoding the length.
// This functionality was available in `lightning` v0.0.123, but has since been
// removed. See the original code here:
// https://docs.rs/lightning/0.0.123/src/lightning/ln/features.rs.html#745-750
// https://docs.rs/lightning/0.0.123/src/lightning/ln/features.rs.html#1008-1012
pub fn encode_bolt11_invoice_features_without_length(features: &Bolt11InvoiceFeatures) -> Vec<u8> {
    let mut feature_bytes = vec![];
    for f in features.le_flags().iter().rev() {
        f.write(&mut feature_bytes)
            .expect("Writing to byte vec can't fail");
    }
    feature_bytes
}

/// Outputs hex into an object implementing `fmt::Write`.
///
/// Vendored from `bitcoin_hashes` v0.11.0:
/// <https://docs.rs/bitcoin_hashes/0.11.0/src/bitcoin_hashes/hex.rs.html#173-189>
pub fn format_hex(data: &[u8], f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let prec = f.precision().unwrap_or(2 * data.len());
    let width = f.width().unwrap_or(2 * data.len());
    for _ in (2 * data.len())..width {
        f.write_str("0")?;
    }
    for ch in data.iter().take(prec / 2) {
        write!(f, "{:02x}", *ch)?;
    }
    if prec < 2 * data.len() && prec % 2 == 1 {
        write!(f, "{:x}", data[prec / 2] / 16)?;
    }
    Ok(())
}

/// Gets the (approximate) network from a bitcoin address.
///
/// This function mimics how `Address.network` is calculated in bitcoin v0.30.
/// However, that field was removed in more recent versions in part because it
/// can only distinguish between `Bitcoin`, `Testnet` and `Regtest`.
///
/// As of bitcoin v0.32.4, `Address::is_valid_for_network()` performs equality
/// checks using `NetworkKind` and `KnownHrp`, which only distinguish between
/// `Bitcoin`, `Testnet` and `Regtest`.
/// <https://docs.rs/bitcoin/0.32.4/src/bitcoin/address/mod.rs.html#709-716>
/// <https://docs.rs/bitcoin/0.32.4/src/bitcoin/network.rs.html#51-58>
/// <https://docs.rs/bitcoin/0.32.4/src/bitcoin/address/mod.rs.html#200-209>
pub fn get_network_for_address(address: &Address<NetworkUnchecked>) -> Network {
    if address.is_valid_for_network(Network::Bitcoin) {
        Network::Bitcoin
    } else if address.is_valid_for_network(Network::Testnet) {
        Network::Testnet
    } else if address.is_valid_for_network(Network::Regtest) {
        Network::Regtest
    } else {
        panic!("Address is not valid for any network");
    }
}

/// Returns the default esplora server according to the network
pub fn default_esplora_server(network: Network, port: Option<String>) -> BitcoinRpcConfig {
    BitcoinRpcConfig {
        kind: "esplora".to_string(),
        url: match network {
            Network::Bitcoin => SafeUrl::parse("https://mempool.space/api/"),
            Network::Testnet => SafeUrl::parse("https://mempool.space/testnet/api/"),
            Network::Testnet4 => SafeUrl::parse("https://mempool.space/testnet4/api/"),
            Network::Signet => SafeUrl::parse("https://mutinynet.com/api/"),
            Network::Regtest => SafeUrl::parse(&format!(
                "http://127.0.0.1:{}/",
                port.unwrap_or_else(|| String::from("50002"))
            )),
            _ => panic!("Failed to parse default esplora server"),
        }
        .expect("Failed to parse default esplora server"),
    }
}

#[cfg(test)]
mod tests;
