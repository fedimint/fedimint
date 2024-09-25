use std::num::ParseIntError;
use std::str::FromStr;

use anyhow::bail;
use bitcoin::Denomination;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::encoding::{Decodable, Encodable};

pub const SATS_PER_BITCOIN: u64 = 100_000_000;

/// Shorthand for [`Amount::from_msats`]
pub fn msats(msats: u64) -> Amount {
    Amount::from_msats(msats)
}

/// Shorthand for [`Amount::from_sats`]
pub fn sats(amount: u64) -> Amount {
    Amount::from_sats(amount)
}

/// Represents an amount of BTC. The base denomination is millisatoshis, which
/// is why the `Amount` type from rust-bitcoin isn't used instead.
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

    /// Create an amount from a number of millisatoshis.
    pub const fn from_msats(msats: u64) -> Amount {
        Amount { msats }
    }

    /// Create an amount from a number of satoshis.
    pub const fn from_sats(sats: u64) -> Amount {
        Amount::from_msats(sats * 1000)
    }

    /// Create an amount from a number of whole bitcoins.
    pub const fn from_bitcoins(bitcoins: u64) -> Amount {
        Amount::from_sats(bitcoins * SATS_PER_BITCOIN)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [FromStr].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        if denom == Denomination::MilliSatoshi {
            return Ok(Self::from_msats(s.parse()?));
        }
        let btc_amt = bitcoin::amount::Amount::from_str_in(s, denom)?;
        Ok(Self::from(btc_amt))
    }

    pub fn saturating_sub(self, other: Amount) -> Self {
        Amount {
            msats: self.msats.saturating_sub(other.msats),
        }
    }

    pub fn mul_u64(self, other: u64) -> Self {
        Amount {
            msats: self.msats * other,
        }
    }

    /// Returns an error if the amount is more precise than satoshis (i.e. if it
    /// has a milli-satoshi remainder). Otherwise, returns `Ok(())`.
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

    pub fn checked_sub(self, other: Amount) -> Option<Self> {
        Some(Self {
            msats: self.msats.checked_sub(other.msats)?,
        })
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            msats: self.msats.checked_add(other.msats)?,
        })
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} msat", self.msats)
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
        self.msats -= rhs.msats;
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

#[derive(Error, Debug)]
pub enum ParseAmountError {
    #[error("Error parsing string as integer: {0}")]
    NotANumber(#[from] ParseIntError),
    #[error("Error parsing string as a bitcoin amount: {0}")]
    WrongBitcoinAmount(#[from] bitcoin::amount::ParseAmountError),
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
}
