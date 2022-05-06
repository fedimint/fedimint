use crate::{Amount, InvalidAmountTierError, Keys};
use minimint_api::encoding::{Decodable, DecodeError, Encodable};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::iter::FromIterator;
use std::marker::PhantomData;

/// Represents coins of different denominations.
///
/// **Attention:** care has to be taken when constructing this to avoid overflow when calculating
/// the total amount represented. As it is prudent to limit both the maximum coin amount and maximum
/// coin count per transaction this shouldn't be a problem in practice though.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Coins<C> {
    pub coins: BTreeMap<Amount, Vec<C>>,
}

pub struct TieredMultiZip<'a, I, C>
where
    I: 'a,
{
    iters: Vec<I>,
    _pd: PhantomData<&'a C>,
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

/// Select coins with total amount of *at least* `amount`. If more than requested amount of coins
/// are returned it was because exact change couldn't be made.
/// The caller can request change from the federation.
impl<C> Coins<C>
where
    C: Clone,
{
    pub fn select_coins(&self, amount: Amount) -> Option<Coins<C>> {
        // Try to select exact change
        let mut selected = Amount::from_msat(0);
        let coins = self
            .iter()
            .rev()
            .filter_map(|(coin_amount, coin)| {
                if amount >= coin_amount + selected {
                    selected += coin_amount;
                    Some((coin_amount, (*coin).clone()))
                } else {
                    None
                }
            })
            .collect::<Coins<C>>();

        if selected == amount {
            return Some(coins);
        }

        // Try to select greater change
        let mut selected = Amount::from_msat(0);
        let coins = self
            .iter()
            .rev()
            .filter_map(|(coin_amount, coin)| {
                if amount > selected {
                    selected += coin_amount;
                    Some((coin_amount, (*coin).clone()))
                } else {
                    None
                }
            })
            .collect::<Coins<C>>();

        if selected >= amount {
            return Some(coins);
        }

        // Insufficient balance
        None
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

impl<C> FromIterator<(Amount, C)> for Coins<C> {
    fn from_iter<T: IntoIterator<Item = (Amount, C)>>(iter: T) -> Self {
        let mut coins = Coins::default();
        coins.extend(iter);
        coins
    }
}

impl<C> IntoIterator for Coins<C>
where
    C: 'static,
{
    type Item = (Amount, C);
    type IntoIter = Box<dyn Iterator<Item = (Amount, C)>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(
            self.coins
                .into_iter()
                .flat_map(|(amt, coins)| coins.into_iter().map(move |c| (amt, c))),
        )
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

impl<C> Encodable for Coins<C>
where
    C: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
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

impl<'a, I, C> TieredMultiZip<'a, I, C> {
    /// Creates a new MultiZip Iterator from `Coins` iterators. These have to be checked for
    /// structural equality! There also has to be at least one iterator in the `iter` vector.
    pub fn new(iters: Vec<I>) -> Self {
        assert!(!iters.is_empty());

        TieredMultiZip {
            iters,
            _pd: Default::default(),
        }
    }
}

impl<'a, I, C> Iterator for TieredMultiZip<'a, I, C>
where
    I: Iterator<Item = (Amount, C)>,
{
    type Item = (Amount, Vec<C>);

    fn next(&mut self) -> Option<Self::Item> {
        let mut coins = Vec::with_capacity(self.iters.len());
        let mut amount = None;
        for iter in self.iters.iter_mut() {
            match iter.next() {
                Some((amt, coin)) => {
                    if let Some(amount) = amount {
                        // This may fail if coins weren't tested for structural equality
                        assert_eq!(amount, amt);
                    } else {
                        amount = Some(amt);
                    }
                    coins.push(coin);
                }
                None => return None,
            }
        }

        // This should always hold as long as this impl is correct
        assert_eq!(coins.len(), self.iters.len());

        Some((
            amount.expect("The multi zip must contain at least one iterator"),
            coins,
        ))
    }
}
