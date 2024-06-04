use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::marker::PhantomData;

use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use serde::{Deserialize, Serialize};

use crate::module::registry::ModuleDecoderRegistry;
use crate::tiered::InvalidAmountTierError;
use crate::{Amount, Tiered};

/// Represents notes of different denominations.
///
/// **Attention:** care has to be taken when constructing this to avoid overflow
/// when calculating the total amount represented. As it is prudent to limit
/// both the maximum note amount and maximum note count per transaction this
/// shouldn't be a problem in practice though.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct TieredMulti<T>(BTreeMap<Amount, Vec<T>>);

impl<T> TieredMulti<T> {
    /// Returns a new `TieredMulti` with the given `BTreeMap` map
    pub fn new(map: BTreeMap<Amount, Vec<T>>) -> Self {
        TieredMulti(map.into_iter().filter(|(_, v)| !v.is_empty()).collect())
    }

    /// Returns the total value of all notes in msat as `Amount`
    pub fn total_amount(&self) -> Amount {
        let milli_sat = self
            .0
            .iter()
            .map(|(tier, notes)| tier.msats * (notes.len() as u64))
            .sum();
        Amount::from_msats(milli_sat)
    }

    /// Returns the number of items in all vectors
    pub fn count_items(&self) -> usize {
        self.0.values().map(Vec::len).sum()
    }

    /// Returns the number of tiers
    pub fn count_tiers(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the keys
    pub fn iter_tiers(&self) -> impl Iterator<Item = &Amount> {
        self.0.keys()
    }

    /// Returns the summary of number of items in each tier
    pub fn summary(&self) -> TieredCounts {
        TieredCounts(
            self.iter()
                .map(|(amount, values)| (*amount, values.len()))
                .collect(),
        )
    }

    /// Verifies whether all vectors in all tiers are empty
    pub fn is_empty(&self) -> bool {
        self.assert_invariants();
        self.count_items() == 0
    }

    /// Verifies whether the structure of `self` and `other` is identical
    pub fn structural_eq<O>(&self, other: &TieredMulti<O>) -> bool {
        let tier_eq = self.0.keys().eq(other.0.keys());
        let per_tier_eq = self
            .0
            .values()
            .zip(other.0.values())
            .all(|(c1, c2)| c1.len() == c2.len());
        tier_eq && per_tier_eq
    }

    /// Returns an borrowing iterator
    pub fn iter(&self) -> impl Iterator<Item = (&Amount, &Vec<T>)> {
        self.0.iter()
    }

    /// Returns an iterator over every `(Amount, &T)`
    ///
    /// Note: The order of the elements is important:
    /// from the lowest tier to the highest, then in order of elements in the
    /// Vec
    pub fn iter_items(&self) -> impl DoubleEndedIterator<Item = (Amount, &T)> {
        // Note: If you change the method implementation, make sure that the returned
        // order of the elements stays consistent.
        self.0
            .iter()
            .flat_map(|(amt, notes)| notes.iter().map(|c| (*amt, c)))
    }

    /// Returns an consuming iterator over every `(Amount, T)`
    ///
    /// Note: The order of the elements is important:
    /// from the lowest tier to the highest, then in order of elements in the
    /// Vec
    pub fn into_iter_items(self) -> impl DoubleEndedIterator<Item = (Amount, T)> {
        // Note: If you change the method implementation, make sure that the returned
        // order of the elements stays consistent.
        self.0
            .into_iter()
            .flat_map(|(amt, notes)| notes.into_iter().map(move |c| (amt, c)))
    }

    /// Returns the length of the longest vector of all tiers, ignoring the
    /// `except` tier
    pub fn longest_tier_except(&self, except: &Amount) -> usize {
        self.0
            .iter()
            .filter_map(|(amt, notes)| {
                if amt == except {
                    None
                } else {
                    Some(notes.len())
                }
            })
            .max()
            .unwrap_or_default()
    }

    /// Verifies that all keys in `self` are present in the keys of the given
    /// parameter `Tiered`
    pub fn all_tiers_exist_in<K>(&self, keys: &Tiered<K>) -> Result<(), InvalidAmountTierError> {
        self.0
            .keys()
            .find(|&amt| keys.get(*amt).is_none())
            .map_or(Ok(()), |amt| Err(InvalidAmountTierError(*amt)))
    }

    /// Returns an `Option` with a reference to the vector of the given `Amount`
    pub fn get(&self, amt: Amount) -> Option<&Vec<T>> {
        self.assert_invariants();
        self.0.get(&amt)
    }

    pub fn push(&mut self, amt: Amount, val: T) {
        self.0.entry(amt).or_default().push(val);
    }

    fn assert_invariants(&self) {
        // Just for compactness and determinism, we don't want entries with 0 items
        #[cfg(debug_assertions)]
        self.iter().for_each(|(_, v)| debug_assert!(!v.is_empty()));
    }
}

impl<C> FromIterator<(Amount, C)> for TieredMulti<C> {
    fn from_iter<T: IntoIterator<Item = (Amount, C)>>(iter: T) -> Self {
        let mut res = TieredMulti::default();
        res.extend(iter);
        res.assert_invariants();
        res
    }
}

impl<C> IntoIterator for TieredMulti<C>
where
    C: 'static + Send,
{
    type Item = (Amount, C);
    type IntoIter = Box<dyn Iterator<Item = (Amount, C)> + Send>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(
            self.0
                .into_iter()
                .flat_map(|(amt, notes)| notes.into_iter().map(move |c| (amt, c))),
        )
    }
}

impl<C> Default for TieredMulti<C> {
    fn default() -> Self {
        TieredMulti(BTreeMap::default())
    }
}

impl<C> Extend<(Amount, C)> for TieredMulti<C> {
    fn extend<T: IntoIterator<Item = (Amount, C)>>(&mut self, iter: T) {
        for (amount, note) in iter {
            self.0.entry(amount).or_default().push(note);
        }
    }
}

impl<C> Encodable for TieredMulti<C>
where
    C: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.consensus_encode(writer)
    }
}

impl<C> Decodable for TieredMulti<C>
where
    C: Decodable + 'static,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(TieredMulti(BTreeMap::consensus_decode_from_finite_reader(
            d, modules,
        )?))
    }
}

pub struct TieredMultiZip<'a, I, T>
where
    I: 'a,
{
    iters: Vec<I>,
    _pd: PhantomData<&'a T>,
}

impl<'a, I, C> TieredMultiZip<'a, I, C> {
    /// Creates a new MultiZip Iterator from `Notes` iterators. These have to be
    /// checked for structural equality! There also has to be at least one
    /// iterator in the `iter` vector.
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
        let mut notes = Vec::with_capacity(self.iters.len());
        let mut amount = None;
        for iter in &mut self.iters {
            match iter.next() {
                Some((amt, note)) => {
                    if let Some(amount) = amount {
                        // This may fail if notes weren't tested for structural equality
                        assert_eq!(amount, amt);
                    } else {
                        amount = Some(amt);
                    }
                    notes.push(note);
                }
                None => return None,
            }
        }

        // This should always hold as long as this impl is correct
        assert_eq!(notes.len(), self.iters.len());

        Some((
            amount.expect("The multi zip must contain at least one iterator"),
            notes,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Default, Serialize, Deserialize, Clone)]
pub struct TieredCounts(Tiered<usize>);

impl TieredCounts {
    pub fn inc(&mut self, tier: Amount, n: usize) {
        if 0 < n {
            *self.0.get_mut_or_default(tier) += n;
        }
    }

    pub fn dec(&mut self, tier: Amount) {
        match self.0.entry(tier) {
            Entry::Vacant(_) => panic!("Trying to decrement an empty tier"),
            Entry::Occupied(mut c) => {
                assert!(*c.get() != 0);
                if *c.get() == 1 {
                    c.remove_entry();
                } else {
                    *c.get_mut() -= 1;
                }
            }
        }
        self.assert_invariants();
    }

    pub fn iter(&self) -> impl Iterator<Item = (Amount, usize)> + '_ {
        self.0.iter().map(|(k, v)| (k, *v))
    }

    pub fn total_amount(&self) -> Amount {
        self.0.iter().map(|(k, v)| k * (*v as u64)).sum::<Amount>()
    }

    pub fn count_items(&self) -> usize {
        self.0.iter().map(|(_, v)| *v).sum()
    }

    pub fn count_tiers(&self) -> usize {
        self.0.count_tiers()
    }

    pub fn is_empty(&self) -> bool {
        self.count_items() == 0
    }

    pub fn get(&self, tier: Amount) -> usize {
        self.assert_invariants();
        self.0.get(tier).copied().unwrap_or_default()
    }

    fn assert_invariants(&self) {
        // Just for compactness and determinism, we don't want entries with 0 count
        #[cfg(debug_assertions)]
        self.iter().for_each(|(_, count)| debug_assert!(0 < count));
    }
}

impl FromIterator<(Amount, usize)> for TieredCounts {
    fn from_iter<I: IntoIterator<Item = (Amount, usize)>>(iter: I) -> Self {
        TieredCounts(iter.into_iter().filter(|(_, count)| *count != 0).collect())
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn summary_works() {
        let notes = TieredMulti::from_iter(vec![
            (Amount::from_sats(1), ()),
            (Amount::from_sats(2), ()),
            (Amount::from_sats(3), ()),
            (Amount::from_sats(3), ()),
            (Amount::from_sats(2), ()),
            (Amount::from_sats(2), ()),
        ]);
        let summary = notes.summary();
        assert_eq!(
            summary.iter().collect::<Vec<_>>(),
            vec![
                (Amount::from_sats(1), 1),
                (Amount::from_sats(2), 3),
                (Amount::from_sats(3), 2),
            ]
        );
        assert_eq!(summary.total_amount(), notes.total_amount());
        assert_eq!(summary.count_items(), notes.count_items());
        assert_eq!(summary.count_tiers(), notes.count_tiers());
    }
}
