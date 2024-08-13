use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::module::registry::ModuleDecoderRegistry;
use crate::{Amount, Tiered};

/// Represents notes of different denominations.
///
/// **Attention:** care has to be taken when constructing this to avoid overflow
/// when calculating the total amount represented. As it is prudent to limit
/// both the maximum note amount and maximum note count per transaction this
/// shouldn't be a problem in practice though.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct TieredMulti<T>(Tiered<Vec<T>>);

impl<T> TieredMulti<T> {
    /// Returns a new `TieredMulti` with the given `BTreeMap` map
    pub fn new(map: BTreeMap<Amount, Vec<T>>) -> Self {
        Self(map.into_iter().filter(|(_, v)| !v.is_empty()).collect())
    }

    /// Returns a new `TieredMulti` from a collection of `Tiered` structs.
    /// The `Tiered` structs are expected to be structurally equal, otherwise
    /// this function will panic.
    pub fn new_aggregate_from_tiered_iter(tiered_iter: impl Iterator<Item = Tiered<T>>) -> Self {
        let mut tiered_multi = Self::default();

        for tiered in tiered_iter {
            for (amt, val) in tiered {
                tiered_multi.push(amt, val);
            }
        }

        // TODO: This only asserts that the output is structurally sound, not the input.
        // For example, an input with tier `Amount`s of [[1, 2], [4, 8]] would currently
        // be accepted even though it is not structurally sound.
        assert!(
            tiered_multi
                .summary()
                .iter()
                .map(|(_tier, count)| count)
                .all_equal(),
            "The supplied Tiered structs were not structurally equal"
        );

        tiered_multi
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
        self.0.count_tiers()
    }

    /// Returns the summary of number of items in each tier
    pub fn summary(&self) -> TieredCounts {
        TieredCounts(
            self.iter()
                .map(|(amount, values)| (amount, values.len()))
                .collect(),
        )
    }

    /// Verifies whether all vectors in all tiers are empty
    pub fn is_empty(&self) -> bool {
        self.assert_invariants();
        self.count_items() == 0
    }

    /// Returns an borrowing iterator
    pub fn iter(&self) -> impl Iterator<Item = (Amount, &Vec<T>)> {
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
            .flat_map(|(amt, notes)| notes.iter().map(move |c| (amt, c)))
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
        let mut res = Self::default();
        res.extend(iter);
        res.assert_invariants();
        res
    }
}

impl<C> IntoIterator for TieredMulti<C>
where
    C: 'static + Send,
{
    type Item = (Amount, Vec<C>);
    type IntoIter = std::collections::btree_map::IntoIter<Amount, Vec<C>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<C> Default for TieredMulti<C> {
    fn default() -> Self {
        Self(Tiered::default())
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
        Ok(Self(Tiered::consensus_decode_from_finite_reader(
            d, modules,
        )?))
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
        Self(iter.into_iter().filter(|(_, count)| *count != 0).collect())
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
