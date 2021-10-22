#![feature(min_type_alias_impl_trait)]

extern crate self as minimint_api;

use bitcoin_hashes::sha256::Hash as Sha256;
pub use bitcoin_hashes::Hash as BitcoinHash;
use bitcoin_hashes::{borrow_slice_impl, hash_newtype, hex_fmt_impl, index_impl, serde_impl};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::iter::FromIterator;
use std::num::ParseIntError;
use std::str::FromStr;
use tbs::{PublicKeyShare, SecretKeyShare};

pub mod config;
pub mod db;
pub mod encoding;
mod keys;
mod module;
pub mod outcome;
pub mod transaction;
mod tweakable;
mod txoproof;
pub mod util;

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::transaction::BlindToken;
pub use keys::CompressedPublicKey;
use miniscript::Descriptor;
pub use module::FederationModule;
use std::io::Error;
pub use tweakable::{Contract, Tweakable};
pub use txoproof::{PegInProof, PegInProofError, TxOutProof};

pub type PegInDescriptor = Descriptor<CompressedPublicKey>;

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

/// Represents coins of different denominations.
///
/// **Attention:** care has to be taken when constructing this to avoid overflow when calculating
/// the total amount represented. As it is prudent to limit both the maximum coin amount and maximum
/// coin count per transaction this shouldn't be a problem in practice though.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Coins<C> {
    pub coins: BTreeMap<Amount, Vec<C>>,
}

/// Represents all tiered keys belonging to a certain entity
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Keys<K> {
    pub keys: BTreeMap<Amount, K>,
}

/// Request to blind sign a certain amount of coins
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SignRequest(pub Coins<tbs::BlindedMessage>);

// FIXME: optimize out blinded msg by making the mint remember it
/// Blind signature share for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PartialSigResponse(pub Coins<(tbs::BlindedMessage, tbs::BlindedSignatureShare)>);

/// Blind signature for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct SigResponse(pub Coins<tbs::BlindedSignature>);

/// A cryptographic coin consisting of a token and a threshold signature by the federated mint. In
/// this form it can oly be validated, not spent since for that the corresponding [`musig::SecKey`]
/// is required.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Coin(pub CoinNonce, pub tbs::Signature);

/// A unique coin nonce which is also a MuSig pub key so that transactions can be signed by the
/// spent coin's spending keys to avoid mint frontrunning.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct CoinNonce(pub secp256k1_zkp::schnorrsig::PublicKey);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub fee_coin_spend_abs: Amount,
    pub fee_peg_in_abs: Amount,
    pub fee_coin_issuance_abs: Amount,
    pub fee_peg_out_abs: Amount,
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

impl Coin {
    /// Verify the coin's validity under a mit key `pk`
    pub fn verify(&self, pk: tbs::AggregatePublicKey) -> bool {
        tbs::verify(self.0.to_message(), self.1, pk)
    }

    /// Access the nonce as the public key to the spend key
    pub fn spend_key(&self) -> &secp256k1_zkp::schnorrsig::PublicKey {
        &self.0 .0
    }
}

impl CoinNonce {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bincode::serialize_into(&mut bytes, &self.0).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        // FIXME: handle errors or the client can be crashed
        bincode::deserialize(bytes).unwrap()
    }

    pub fn to_message(&self) -> tbs::Message {
        let mut hasher = sha3::Sha3_256::default();
        bincode::serialize_into(&mut hasher, &self.0).unwrap();
        tbs::Message::from_hash(hasher)
    }
}

impl<C> Coins<C> {
    pub fn amount(&self) -> Amount {
        let milli_sat = self
            .coins
            .iter()
            .map(|(tier, coins)| tier.milli_sat * (coins.len() as u64))
            .sum();
        Amount { milli_sat }
    }

    pub fn coin_count(&self) -> usize {
        self.coins.iter().map(|(_, coins)| coins.len()).sum()
    }

    pub fn coin_amount_tiers(&self) -> impl Iterator<Item = &Amount> {
        self.coins.keys()
    }

    pub fn map<F, N, E>(self, f: F) -> Result<Coins<N>, E>
    where
        F: Fn(Amount, C) -> Result<N, E>,
    {
        let coins = self
            .coins
            .into_iter()
            .map(|(amt, coins)| -> Result<_, E> {
                let coins = coins
                    .into_iter()
                    .map(|coin| f(amt, coin))
                    .collect::<Result<Vec<_>, E>>()?;
                Ok((amt, coins))
            })
            .collect::<Result<BTreeMap<Amount, Vec<N>>, E>>()?;

        Ok(Coins { coins })
    }

    pub fn structural_eq<O>(&self, other: &Coins<O>) -> bool {
        let tier_eq = self.coins.keys().eq(other.coins.keys());
        let coins_per_tier_eq = self
            .coins
            .values()
            .zip(other.coins.values())
            .all(|(c1, c2)| c1.len() == c2.len());

        tier_eq && coins_per_tier_eq
    }

    pub fn iter(&self) -> impl Iterator<Item = (Amount, &C)> + DoubleEndedIterator {
        self.coins
            .iter()
            .flat_map(|(amt, coins)| coins.iter().map(move |c| (*amt, c)))
    }

    pub fn check_tiers<K>(&self, keys: &Keys<K>) -> Result<(), InvalidAmountTierError> {
        match self.coins.keys().find(|amt| !keys.keys.contains_key(amt)) {
            Some(amt) => Err(InvalidAmountTierError(*amt)),
            None => Ok(()),
        }
    }
}
impl<C> Coins<C>
where
    C: Clone,
{
    pub fn select_coins(&self, mut amount: Amount) -> Option<Coins<C>> {
        let coins = self
            .iter()
            .rev()
            .filter_map(|(amt, coin)| {
                if amount >= amt {
                    amount -= amt;
                    Some((amt, (*coin).clone()))
                } else {
                    None
                }
            })
            .collect::<Coins<C>>();

        if amount == Amount::ZERO {
            Some(coins)
        } else {
            None
        }
    }
}

impl Coins<()> {
    pub fn represent_amount<K>(mut amount: Amount, tiers: &Keys<K>) -> Coins<()> {
        let coins = tiers
            .keys
            .keys()
            .rev()
            .map(|&amount_tier| {
                let res = amount / amount_tier;
                amount %= amount_tier;
                (amount_tier, vec![(); res as usize])
            })
            .collect();

        Coins { coins }
    }
}

impl Amount {
    pub const ZERO: Self = Self { milli_sat: 0 };

    pub fn from_msat(msat: u64) -> Amount {
        Amount { milli_sat: msat }
    }

    pub fn from_sat(sat: u64) -> Amount {
        Amount {
            milli_sat: sat * 1000,
        }
    }

    pub fn saturating_sub(self, other: Amount) -> Self {
        Amount {
            milli_sat: self.milli_sat.saturating_sub(other.milli_sat),
        }
    }
}

impl<C> FromIterator<(Amount, C)> for Coins<C> {
    fn from_iter<T: IntoIterator<Item = (Amount, C)>>(iter: T) -> Self {
        let mut coins = Coins::default();
        coins.extend(iter);
        coins
    }
}

impl<C> IntoIterator for Coins<C> {
    type Item = (Amount, C);
    type IntoIter = impl Iterator<Item = (Amount, C)>;

    fn into_iter(self) -> Self::IntoIter {
        self.coins
            .into_iter()
            .flat_map(|(amt, coins)| coins.into_iter().map(move |c| (amt, c)))
    }
}

impl<C> Default for Coins<C> {
    fn default() -> Self {
        Coins {
            coins: BTreeMap::default(),
        }
    }
}

impl<C> Extend<(Amount, C)> for Coins<C> {
    fn extend<T: IntoIterator<Item = (Amount, C)>>(&mut self, iter: T) {
        for (amount, coin) in iter {
            self.coins.entry(amount).or_default().push(coin)
        }
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} msat", self.milli_sat)
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
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Amount {
            milli_sat: s.parse()?,
        })
    }
}

impl<K> Keys<K> {
    pub fn structural_eq<O>(&self, other: &Keys<O>) -> bool {
        self.keys.keys().eq(other.keys.keys())
    }

    /// Returns a reference to the key of the specified tier
    pub fn tier(&self, amount: &Amount) -> Result<&K, InvalidAmountTierError> {
        self.keys.get(amount).ok_or(InvalidAmountTierError(*amount))
    }

    pub fn tiers(&self) -> impl Iterator<Item = &Amount> {
        self.keys.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Amount, &K)> {
        self.keys.iter().map(|(amt, key)| (*amt, key))
    }
}

impl Keys<SecretKeyShare> {
    pub fn to_public(&self) -> Keys<PublicKeyShare> {
        Keys {
            keys: self
                .keys
                .iter()
                .map(|(amt, key)| (*amt, key.to_pub_key_share()))
                .collect(),
        }
    }
}

impl<K> FromIterator<(Amount, K)> for Keys<K> {
    fn from_iter<T: IntoIterator<Item = (Amount, K)>>(iter: T) -> Self {
        Keys {
            keys: iter.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct InvalidAmountTierError(pub Amount);

impl std::fmt::Display for InvalidAmountTierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Amount tier unknown to mint: {}", self.0)
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

impl<C> Encodable for Coins<C>
where
    C: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut len = 0;
        len += (self.iter().count() as u64).consensus_encode(&mut writer)?;
        for (amount, coin) in self.iter() {
            len += amount.consensus_encode(&mut writer)?;
            len += coin.consensus_encode(&mut writer)?;
        }
        Ok(len)
    }
}

impl<C> Decodable for Coins<C>
where
    C: Decodable,
{
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut coins = BTreeMap::new();
        let len = u64::consensus_decode(&mut d)?;
        for _ in 0..len {
            let amt = Amount::consensus_decode(&mut d)?;
            let coin = C::consensus_decode(&mut d)?;
            coins.entry(amt).or_insert_with(Vec::new).push(coin);
        }
        Ok(Coins { coins })
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

impl From<SignRequest> for Coins<BlindToken> {
    fn from(sig_req: SignRequest) -> Self {
        sig_req
            .0
            .into_iter()
            .map(|(amt, token)| (amt, crate::transaction::BlindToken(token)))
            .collect()
    }
}
