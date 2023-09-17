#![allow(where_clauses_object_safety)] // https://github.com/dtolnay/async-trait/issues/228
extern crate self as fedimint_core;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Error;
use std::num::ParseIntError;
use std::str::FromStr;

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

#[cfg(not(target_family = "wasm"))]
pub mod admin_client;
pub mod api;
pub mod backup;
pub mod bitcoinrpc;
pub mod cancellable;
pub mod config;
pub mod core;
pub mod db;
pub mod encoding;
pub mod epoch;
pub mod fmt_utils;
pub mod hex;
#[macro_use]
pub mod macros;
pub mod module;
pub mod net;
pub mod query;
pub mod task;
pub mod tiered;
pub mod tiered_multi;
pub mod time;
pub mod timing;
pub mod transaction;
pub mod txoproof;
pub mod util;

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

    pub const fn from_msats(msat: u64) -> Amount {
        Amount { msats: msat }
    }

    pub const fn from_sats(sat: u64) -> Amount {
        Amount { msats: sat * 1000 }
    }

    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        if let Denomination::MilliSatoshi = denom {
            return Self::from_str(s);
        }
        let btc_amt = bitcoin::util::amount::Amount::from_str_in(s, denom)?;
        Ok(Self::from(btc_amt))
    }

    pub fn saturating_sub(self, other: Amount) -> Self {
        Amount {
            msats: self.msats.saturating_sub(other.msats),
        }
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

impl<T> NumPeers for BTreeMap<PeerId, T> {
    fn total(&self) -> usize {
        self.len()
    }
}

impl NumPeers for &[PeerId] {
    fn total(&self) -> usize {
        self.len()
    }
}

impl NumPeers for Vec<PeerId> {
    fn total(&self) -> usize {
        self.len()
    }
}

impl NumPeers for Vec<PeerUrl> {
    fn total(&self) -> usize {
        self.len()
    }
}

impl NumPeers for BTreeSet<PeerId> {
    fn total(&self) -> usize {
        self.len()
    }
}

/// for consensus-related calculations given the number of peers
pub trait NumPeers {
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
        Ok(Amount { msats: s.parse()? })
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
        let sats = self.sats_per_kvb * weight / 1000;
        bitcoin::Amount::from_sat(sats)
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Mismatching outcome variant: expected {0}, got {1}")]
    MismatchingVariant(&'static str, &'static str),
}
