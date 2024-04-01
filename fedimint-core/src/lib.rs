//! Fedimint Core library
//!
//! `fedimint-core` contains are commonly used types, utilities and primitives,
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

#![allow(where_clauses_object_safety)] // https://github.com/dtolnay/async-trait/issues/228
extern crate self as fedimint_core;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::io::Error;
use std::num::ParseIntError;
use std::str::FromStr;

use anyhow::bail;
use bitcoin::Denomination;
use bitcoin_hashes::hash_newtype;
use bitcoin_hashes::sha256::Hash as Sha256;
pub use bitcoin_hashes::Hash as BitcoinHash;
use fedimint_core::config::PeerUrl;
pub use macro_rules_attribute::apply;
pub use module::ServerModule;
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub use tiered::Tiered;
pub use tiered_multi::*;

pub use crate::core::server;
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

/// Admin (guardian) client types
pub mod admin_client;
/// Client API request handling
pub mod api;
/// Federation-stored client backups
pub mod backup;
/// Gradual bitcoin dependency migration helpers
pub mod bitcoin_migration;
/// Legacy serde encoding for bls12_381
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
/// Hex encoding helpers
pub mod hex;
/// Common macros
#[macro_use]
pub mod macros;
/// Extenable module sysystem
pub mod module;
/// Peer networking
pub mod net;
/// Client query system
pub mod query;
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

/// Atomic BFT unit containing consensus items
pub mod session_outcome;

hash_newtype!(
    TransactionId,
    Sha256,
    32,
    doc = "A transaction id for peg-ins, peg-outs and reissuances"
);

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct PeerId(u16);

impl FromStr for PeerId {
    type Err = <u16 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(PeerId)
    }
}

pub const SATS_PER_BITCOIN: u64 = 100_000_000;

/// Represents an amount of BTC inside the system. The base denomination is
/// milli satoshi for now, this is also why the amount type from rust-bitcoin
/// isn't used instead.
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deserialize,
    Serialize,
    Encodable,
    Decodable,
)]
#[serde(transparent)]
pub struct Amount {
    pub msats: u64,
}

impl Amount {
    pub const ZERO: Self = Self { msats: 0 };

    pub const fn from_msats(msats: u64) -> Amount {
        Amount { msats }
    }

    pub const fn from_sats(sats: u64) -> Amount {
        Amount::from_msats(sats * 1000)
    }

    pub const fn from_bitcoins(bitcoins: u64) -> Amount {
        Amount::from_sats(bitcoins * SATS_PER_BITCOIN)
    }

    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        if let Denomination::MilliSatoshi = denom {
            return Ok(Self::from_msats(s.parse()?));
        }
        let btc_amt = bitcoin::util::amount::Amount::from_str_in(s, denom)?;
        Ok(Self::from(btc_amt))
    }

    pub fn saturating_sub(self, other: Amount) -> Self {
        Amount {
            msats: self.msats.saturating_sub(other.msats),
        }
    }

    // Makes sure we're dealing with a precision of satoshi or higher
    pub fn ensure_sats_precision(&self) -> anyhow::Result<()> {
        if self.msats % 1000 != 0 {
            bail!("Amount is using a precision smaller than satoshi, cannot convert to satoshis");
        }
        Ok(())
    }

    pub fn try_into_sats(&self) -> anyhow::Result<u64> {
        self.ensure_sats_precision()?;
        Ok(self.msats / 1000)
    }

    pub const fn sats_round_down(&self) -> u64 {
        self.msats / 1000
    }

    pub fn sats_f64(&self) -> f64 {
        self.msats as f64 / 1000.0
    }
}

/// Shorthand for [`Amount::from_msats`]
///
/// Useful only for tests, but it's so common that it makes sense to have
/// it in the main `fedimint-api` crate.
pub fn msats(msats: u64) -> Amount {
    Amount::from_msats(msats)
}

/// Shorthand for [`Amount::from_sats`]
pub fn sats(amount: u64) -> Amount {
    Amount::from_sats(amount)
}

pub mod amount {
    pub mod serde {
        pub mod as_msat {
            //! Serialize and deserialize [`Amount`](crate::Amount) as integers
            //! denominated in milli-satoshi. Use with
            //! `#[serde(with = "amount::serde::as_msat")]`.

            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            pub fn serialize<S: Serializer>(a: &crate::Amount, s: S) -> Result<S::Ok, S::Error> {
                u64::serialize(&a.msats, s)
            }

            pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<crate::Amount, D::Error> {
                Ok(crate::Amount::from_msats(u64::deserialize(d)?))
            }
        }
    }
}

/// Amount of bitcoin to send, or "all" to send all available funds
#[derive(Debug, Eq, PartialEq, Copy, Hash, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinAmountOrAll {
    All,
    #[serde(untagged)]
    Amount(#[serde(with = "bitcoin::util::amount::serde::as_sat")] bitcoin::Amount),
}

impl FromStr for BitcoinAmountOrAll {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s == "all" {
            Ok(BitcoinAmountOrAll::All)
        } else {
            let amount = crate::Amount::from_str(s)?;
            Ok(BitcoinAmountOrAll::Amount(amount.try_into()?))
        }
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

#[derive(Error, Debug)]
pub enum ParseAmountError {
    #[error("Error parsing string as integer: {0}")]
    NotANumber(#[from] ParseIntError),
    #[error("Error parsing string as a bitcoin amount: {0}")]
    WrongBitcoinAmount(#[from] bitcoin::util::amount::ParseAmountError),
}

impl<T> NumPeersExt for BTreeMap<PeerId, T> {
    fn total(&self) -> usize {
        self.len()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NumPeers(usize);

impl From<usize> for NumPeers {
    fn from(value: usize) -> Self {
        Self(value)
    }
}
impl NumPeers {
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl NumPeersExt for NumPeers {
    fn total(&self) -> usize {
        self.0
    }
}

impl NumPeersExt for &[PeerId] {
    fn total(&self) -> usize {
        self.len()
    }
}

impl NumPeersExt for Vec<PeerId> {
    fn total(&self) -> usize {
        self.len()
    }
}

impl NumPeersExt for Vec<PeerUrl> {
    fn total(&self) -> usize {
        self.len()
    }
}

impl NumPeersExt for BTreeSet<PeerId> {
    fn total(&self) -> usize {
        self.len()
    }
}

/// for consensus-related calculations given the number of peers
pub trait NumPeersExt {
    fn total(&self) -> usize;

    /// number of peers that can be evil without disrupting the federation
    fn max_evil(&self) -> usize {
        (self.total() - 1) / 3
    }

    /// number of peers to select such that one is honest (under our
    /// assumptions)
    fn one_honest(&self) -> usize {
        self.max_evil() + 1
    }

    /// Degree of a underlying polynomial to require `threshold` signatures
    fn degree(&self) -> usize {
        self.threshold() - 1
    }

    /// number of peers required for a signature
    fn threshold(&self) -> usize {
        self.total() - self.max_evil()
    }
}

impl PeerId {
    pub fn to_usize(self) -> usize {
        self.0 as usize
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for PeerId {
    fn from(id: u16) -> Self {
        Self(id)
    }
}

impl From<PeerId> for u16 {
    fn from(peer: PeerId) -> u16 {
        peer.0
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} msat", self.msats)
    }
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.out_idx)
    }
}

impl std::ops::Rem for Amount {
    type Output = Amount;

    fn rem(self, rhs: Self) -> Self::Output {
        Amount {
            msats: self.msats % rhs.msats,
        }
    }
}

impl std::ops::RemAssign for Amount {
    fn rem_assign(&mut self, rhs: Self) {
        self.msats %= rhs.msats;
    }
}

impl std::ops::Div for Amount {
    type Output = u64;

    fn div(self, rhs: Self) -> Self::Output {
        self.msats / rhs.msats
    }
}

impl std::ops::SubAssign for Amount {
    fn sub_assign(&mut self, rhs: Self) {
        self.msats -= rhs.msats
    }
}

impl std::ops::Mul<u64> for Amount {
    type Output = Amount;

    fn mul(self, rhs: u64) -> Self::Output {
        Amount {
            msats: self.msats * rhs,
        }
    }
}

impl std::ops::Mul<Amount> for u64 {
    type Output = Amount;

    fn mul(self, rhs: Amount) -> Self::Output {
        Amount {
            msats: self * rhs.msats,
        }
    }
}

impl std::ops::Add for Amount {
    type Output = Amount;

    fn add(self, rhs: Self) -> Self::Output {
        Amount {
            msats: self.msats + rhs.msats,
        }
    }
}

impl std::ops::AddAssign for Amount {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::iter::Sum for Amount {
    fn sum<I: Iterator<Item = Amount>>(iter: I) -> Self {
        Amount {
            msats: iter.map(|amt| amt.msats).sum::<u64>(),
        }
    }
}

impl std::ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Self) -> Self::Output {
        Amount {
            msats: self.msats - rhs.msats,
        }
    }
}

impl FromStr for Amount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(i) = s.find(char::is_alphabetic) {
            let (amt, denom) = s.split_at(i);
            Amount::from_str_in(amt.trim(), denom.trim().parse()?)
        } else {
            // default to millisatoshi
            Amount::from_str_in(s.trim(), bitcoin::Denomination::MilliSatoshi)
        }
    }
}

impl From<bitcoin::Amount> for Amount {
    fn from(amt: bitcoin::Amount) -> Self {
        assert!(amt.to_sat() <= 2_100_000_000_000_000);
        Amount {
            msats: amt.to_sat() * 1000,
        }
    }
}

impl TryFrom<Amount> for bitcoin::Amount {
    type Error = anyhow::Error;

    fn try_from(value: Amount) -> anyhow::Result<Self> {
        value.try_into_sats().map(bitcoin::Amount::from_sat)
    }
}

impl Encodable for TransactionId {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let bytes = &self[..];
        writer.write_all(bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for TransactionId {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(TransactionId::from_inner(bytes))
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

impl Feerate {
    pub fn calculate_fee(&self, weight: u64) -> bitcoin::Amount {
        let sats = weight_to_vbytes(weight) * self.sats_per_kvb / 1000;
        bitcoin::Amount::from_sat(sats)
    }
}

const WITNESS_SCALE_FACTOR: u64 = bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR as u64;

/// Converts weight to virtual bytes, defined in [BIP-141] as weight / 4
/// (rounded up to the next integer).
///
/// [BIP-141]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-size-calculations
pub fn weight_to_vbytes(weight: u64) -> u64 {
    (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Mismatching outcome variant: expected {0}, got {1}")]
    MismatchingVariant(&'static str, &'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_multiplication_by_scalar() {
        assert_eq!(Amount::from_msats(1000) * 123, Amount::from_msats(123_000));
    }

    #[test]
    fn scalar_multiplication_by_amount() {
        assert_eq!(123 * Amount::from_msats(1000), Amount::from_msats(123_000));
    }

    #[test]
    fn converts_weight_to_vbytes() {
        assert_eq!(1, weight_to_vbytes(4));
        assert_eq!(2, weight_to_vbytes(5));
    }

    #[test]
    fn calculate_fee() {
        let feerate = Feerate { sats_per_kvb: 1000 };
        assert_eq!(bitcoin::Amount::from_sat(25), feerate.calculate_fee(100));
        assert_eq!(bitcoin::Amount::from_sat(26), feerate.calculate_fee(101));
    }

    #[test]
    fn test_amount_parsing() {
        // msats
        assert_eq!(Amount::from_msats(123), Amount::from_str("123").unwrap());
        assert_eq!(
            Amount::from_msats(123),
            Amount::from_str("123msat").unwrap()
        );
        assert_eq!(
            Amount::from_msats(123),
            Amount::from_str("123 msat").unwrap()
        );
        assert_eq!(
            Amount::from_msats(123),
            Amount::from_str("123 msats").unwrap()
        );
        // sats
        assert_eq!(Amount::from_sats(123), Amount::from_str("123sat").unwrap());
        assert_eq!(Amount::from_sats(123), Amount::from_str("123 sat").unwrap());
        assert_eq!(
            Amount::from_sats(123),
            Amount::from_str("123satoshi").unwrap()
        );
        assert_eq!(
            Amount::from_sats(123),
            Amount::from_str("123satoshis").unwrap()
        );
        // btc
        assert_eq!(
            Amount::from_bitcoins(123),
            Amount::from_str("123btc").unwrap()
        );
        assert_eq!(
            Amount::from_sats(12_345_600_000),
            Amount::from_str("123.456btc").unwrap()
        );
    }

    #[test]
    fn test_deserialize_amount_or_all() {
        let all: BitcoinAmountOrAll = serde_json::from_str("\"all\"").unwrap();
        assert_eq!(all, BitcoinAmountOrAll::All);

        let all: BitcoinAmountOrAll = serde_json::from_str("12345").unwrap();
        assert_eq!(
            all,
            BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(12345))
        );
    }
}
