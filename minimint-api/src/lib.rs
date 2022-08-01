extern crate self as minimint_api;

use bitcoin::Denomination;
use bitcoin_hashes::sha256::Hash as Sha256;
pub use bitcoin_hashes::Hash as BitcoinHash;
use bitcoin_hashes::{borrow_slice_impl, hash_newtype, hex_fmt_impl, index_impl, serde_impl};
pub use module::{FederationModule, InputMeta};
use serde::{Deserialize, Serialize};
use std::io::Error;
use std::num::ParseIntError;
use std::str::FromStr;
use thiserror::Error;

use crate::encoding::{Decodable, DecodeError, Encodable};

pub mod config;
pub mod db;
pub mod encoding;
pub mod module;
pub mod net;
pub mod rand;
pub mod task;

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
        assert!(amt.as_sat() <= 2_100_000_000_000_000);
        Amount {
            milli_sat: amt.as_sat() * 1000,
        }
    }
}

impl Encodable for TransactionId {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, Error> {
        let bytes = &self[..];
        writer.write_all(bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for TransactionId {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(TransactionId::from_inner(bytes))
    }
}
