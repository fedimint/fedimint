#![feature(type_alias_impl_trait)]

use bitcoin_hashes::sha256::Hash as Sha256;
pub use bitcoin_hashes::Hash as BitcoinHash;
use bitcoin_hashes::{borrow_slice_impl, hash_newtype, hex_fmt_impl, index_impl, serde_impl};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::iter::FromIterator;
use std::num::ParseIntError;
use std::str::FromStr;

pub mod util;

hash_newtype!(
    TransactionId,
    Sha256,
    32,
    doc = "A transaction id for peg-ins, peg-outs and reissuances"
);

/// Represents an amount of BTC inside the system. The base denomination is milli satoshi for now,
/// this is also why the amount type from rust-bitcoin isn't used instead.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SignRequest(pub Coins<tbs::BlindedMessage>);

// FIXME: optimize out blinded msg by making the mint remember it
/// Blind signature share for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PartialSigResponse(pub Coins<(tbs::BlindedMessage, tbs::BlindedSignatureShare)>);

/// Blind signature for a [`SignRequest`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SigResponse(pub Coins<tbs::BlindedSignature>);

/// A cryptographic coin consisting of a token and a threshold signature by the federated mint. In
/// this form it can oly be validated, not spent since for that the corresponding [`musig::SecKey`]
/// is required.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Coin(pub CoinNonce, pub tbs::Signature);

/// A unique coin nonce which is also a MuSig pub key so that transactions can be signed by the
/// spent coin's spending keys to avoid mint frontrunning.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct CoinNonce(pub musig::PubKey);

/// After sending bitcoins to the federation wallet a client can request the appropriate amount
/// of coins in return using this request.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PegInRequest {
    pub blind_tokens: SignRequest,
    pub proof: (), // TODO: implement pegin
}

/// Exchange already signed [`Coin`]s for new coins, breaking the link due to blind signing
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct ReissuanceRequest {
    pub coins: Coins<Coin>,
    pub blind_tokens: SignRequest,
    pub sig: musig::Sig,
}

/// Redeem [`Coin`]s for bitcoin on-chain
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PegOutRequest {
    pub address: (), // TODO: implement pegout
    pub coins: Coins<Coin>,
    pub sig: (), // TODO: impl signing
}

/// This object belongs to an issuance operation and thus has an [`IssuanceId`]
pub trait TxId {
    /// Calculate [`IssuanceId`]
    fn id(&self) -> TransactionId;
}

impl TxId for PegInRequest {
    fn id(&self) -> TransactionId {
        let mut hasher = Sha256::engine();
        bincode::serialize_into(&mut hasher, &self.blind_tokens).expect("encoding error");
        bincode::serialize_into(&mut hasher, &self.proof).expect("encoding error");
        TransactionId(Sha256::from_engine(hasher))
    }
}

impl TxId for ReissuanceRequest {
    fn id(&self) -> TransactionId {
        let mut hasher = Sha256::engine();
        bincode::serialize_into(&mut hasher, &self.coins).expect("encoding error");
        bincode::serialize_into(&mut hasher, &self.blind_tokens).expect("encoding error");
        TransactionId(Sha256::from_engine(hasher))
    }
}

impl TxId for PegOutRequest {
    fn id(&self) -> TransactionId {
        let mut hasher = Sha256::engine();
        bincode::serialize_into(&mut hasher, &self.coins).expect("encoding error");
        bincode::serialize_into(&mut hasher, &self.address).expect("encoding error");
        TransactionId(Sha256::from_engine(hasher))
    }
}

impl Coin {
    /// Verify the coin's validity under a mit key `pk`
    pub fn verify(&self, pk: tbs::AggregatePublicKey) -> bool {
        tbs::verify(self.0.to_message(), self.1, pk)
    }

    /// Access the nonce as the public key to the spend key
    pub fn spend_key(&self) -> &musig::PubKey {
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

    pub fn iter(&self) -> impl Iterator<Item = (Amount, &C)> {
        self.coins
            .iter()
            .flat_map(|(amt, coins)| coins.iter().map(move |c| (*amt, c)))
    }

    pub fn has_valid_tiers<K>(&self, keys: &Keys<K>) -> Result<(), InvalidAmountTierError> {
        match self.coins.keys().find(|amt| !keys.keys.contains_key(amt)) {
            Some(amt) => Err(InvalidAmountTierError(*amt)),
            None => Ok(()),
        }
    }
}

impl Coins<()> {
    pub fn represent_amount(mut amount: Amount, tiers: &BTreeSet<Amount>) -> Coins<()> {
        let coins = tiers
            .iter()
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
    pub fn from_msat(msat: u64) -> Amount {
        Amount { milli_sat: msat }
    }

    pub fn from_sat(sat: u64) -> Amount {
        Amount {
            milli_sat: sat * 1000,
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
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct InvalidAmountTierError(Amount);

impl std::fmt::Display for InvalidAmountTierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Amount tier unknown to mint: {}", self.0)
    }
}
