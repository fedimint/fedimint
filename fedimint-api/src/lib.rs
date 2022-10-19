extern crate self as fedimint_api;

use std::collections::BTreeMap;
use std::io::Error;
use std::num::ParseIntError;
use std::str::FromStr;

use bitcoin::Denomination;
pub use bitcoin_hashes;
use bitcoin_hashes::hash_newtype;
use bitcoin_hashes::sha256::Hash as Sha256;
pub use bitcoin_hashes::Hash as BitcoinHash;
pub use module::InputMeta;
use module::ModuleDecoder;
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub use tiered::Tiered;
pub use tiered_multi::*;

use crate::encoding::{Decodable, DecodeError, Encodable, ModuleRegistry};

pub mod config;
pub mod db;
pub mod encoding;
pub mod macros;
pub mod module;
pub mod net;
pub mod task;
pub mod tiered;
pub mod tiered_multi;
pub mod transaction;

pub use serde_json;

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

/// Represents an amount of BTC inside the system. The base denomination is milli satoshi for now,
/// this is also why the amount type from rust-bitcoin isn't used instead.
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
    pub milli_sat: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutPoint {
    pub txid: TransactionId,
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

/// for consensus-related calculations given the number of peers
pub trait NumPeers {
    fn total(&self) -> usize;

    /// number of peers that can be evil without disrupting the federation
    fn max_evil(&self) -> usize {
        (self.total() - 1) / 3
    }

    /// number of peers to select such that one is honest (under our assumptions)
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

impl Amount {
    pub const ZERO: Self = Self { milli_sat: 0 };

    pub const fn from_msat(msat: u64) -> Amount {
        Amount { milli_sat: msat }
    }

    pub const fn from_sat(sat: u64) -> Amount {
        Amount {
            milli_sat: sat * 1000,
        }
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
            milli_sat: self.milli_sat.saturating_sub(other.milli_sat),
        }
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} msat", self.milli_sat)
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
            milli_sat: self.milli_sat % rhs.milli_sat,
        }
    }
}

impl std::ops::RemAssign for Amount {
    fn rem_assign(&mut self, rhs: Self) {
        self.milli_sat %= rhs.milli_sat;
    }
}

impl std::ops::Div for Amount {
    type Output = u64;

    fn div(self, rhs: Self) -> Self::Output {
        self.milli_sat / rhs.milli_sat
    }
}

impl std::ops::SubAssign for Amount {
    fn sub_assign(&mut self, rhs: Self) {
        self.milli_sat -= rhs.milli_sat
    }
}

impl std::ops::Mul<u64> for Amount {
    type Output = Amount;

    fn mul(self, rhs: u64) -> Self::Output {
        Amount {
            milli_sat: self.milli_sat * rhs,
        }
    }
}

impl std::ops::Add for Amount {
    type Output = Amount;

    fn add(self, rhs: Self) -> Self::Output {
        Amount {
            milli_sat: self.milli_sat + rhs.milli_sat,
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
            milli_sat: iter.map(|amt| amt.milli_sat).sum::<u64>(),
        }
    }
}

impl std::ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Self) -> Self::Output {
        Amount {
            milli_sat: self.milli_sat - rhs.milli_sat,
        }
    }
}

impl FromStr for Amount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Amount {
            milli_sat: s.parse()?,
        })
    }
}

impl From<bitcoin::Amount> for Amount {
    fn from(amt: bitcoin::Amount) -> Self {
        assert!(amt.to_sat() <= 2_100_000_000_000_000);
        Amount {
            milli_sat: amt.to_sat() * 1000,
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
    fn consensus_decode<M, D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleRegistry<M>,
    ) -> Result<Self, DecodeError>
    where
        M: ModuleDecoder,
    {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(TransactionId::from_inner(bytes))
    }
}
