use std::cmp::min;
use std::collections::BTreeMap;
use std::iter::FromIterator;
use std::marker::PhantomData;

use fedimint_api::encoding::{Decodable, DecodeError, Encodable};
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
        TieredMulti(map)
    }

    /// Returns the total value of all notes in msat as `Amount`
    pub fn total_amount(&self) -> Amount {
        let milli_sat = self
            .0
            .iter()
            .map(|(tier, notes)| tier.msats * (notes.len() as u64))
            .sum();
        Amount { msats: milli_sat }
    }

    /// Returns the number of items in all vectors
    pub fn count_items(&self) -> usize {
        self.0.values().map(|notes| notes.len()).sum()
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
    pub fn summary(&self) -> Tiered<usize> {
        Tiered::from_iter(self.iter().map(|(amount, values)| (*amount, values.len())))
    }

    /// Verifies whether all vectors in all tiers are empty
    pub fn is_empty(&self) -> bool {
        self.count_items() == 0
    }

    /// Applies the given closure to every `(Amount, T)` pair
    pub fn map<F, N, E>(self, f: F) -> Result<TieredMulti<N>, E>
    where
        F: Fn(Amount, T) -> Result<N, E>,
    {
        let res = self
            .0
            .into_iter()
            .map(|(amt, notes)| -> Result<_, E> {
                let notes = notes
                    .into_iter()
                    .map(|note| f(amt, note))
                    .collect::<Result<Vec<_>, E>>()?;
                Ok((amt, notes))
            })
            .collect::<Result<BTreeMap<Amount, Vec<N>>, E>>()?;

        Ok(TieredMulti(res))
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
    pub fn iter_items(&self) -> impl Iterator<Item = (Amount, &T)> + DoubleEndedIterator {
        // Note: If you change the method implementation, make sure that the returned
        // order of the elements stays consistent.
        self.0
            .iter()
            .flat_map(|(amt, notes)| notes.iter().map(move |c| (*amt, c)))
    }

    /// Returns an consuming iterator over every `(Amount, T)`
    ///
    /// Note: The order of the elements is important:
    /// from the lowest tier to the highest, then in order of elements in the
    /// Vec
    pub fn into_iter_items(self) -> impl Iterator<Item = (Amount, T)> + DoubleEndedIterator {
        // Note: If you change the method implementation, make sure that the returned
        // order of the elements stays consistent.
        self.0
            .into_iter()
            .flat_map(|(amt, notes)| notes.into_iter().map(move |c| (amt, c)))
    }

    /// Returns the length of the longest vector of all tiers
    pub fn longest_tier_len(&self) -> usize {
        self.0.values().map(|notes| notes.len()).max().unwrap_or(0)
    }

    /// Verifies that all keys in `self` are present in the keys of the given
    /// parameter `Tiered`
    pub fn all_tiers_exist_in<K>(&self, keys: &Tiered<K>) -> Result<(), InvalidAmountTierError> {
        match self.0.keys().find(|&amt| keys.get(*amt).is_none()) {
            Some(amt) => Err(InvalidAmountTierError(*amt)),
            None => Ok(()),
        }
    }

    /// Returns an `Option` with a reference to the vector of the given `Amount`
    pub fn get(&self, amt: Amount) -> Option<&Vec<T>> {
        self.0.get(&amt)
    }

    // TODO: Get rid of it. It might be used to break useful invariants (like making
    // sure there are no empty `Vec`s after removal)
    pub fn get_mut(&mut self, amt: Amount) -> Option<&mut Vec<T>> {
        self.0.get_mut(&amt)
    }
}

impl<C> TieredMulti<C>
where
    C: Clone,
{
    /// Select notes with total amount of *at least* `amount`. If more than
    /// requested amount of notes are returned it was because exact change
    /// couldn't be made, and the next smallest amount will be returned.
    ///
    /// The caller can request change from the federation.
    // TODO: move somewhere else?
    pub fn select_notes(&self, mut amount: Amount) -> Option<TieredMulti<C>> {
        if amount > self.total_amount() {
            return None;
        }

        let mut selected = vec![];
        let mut remaining = self.total_amount();

        for (note_amount, note) in self.iter_items().rev() {
            remaining -= note_amount;

            if note_amount <= amount {
                amount -= note_amount;
                selected.push((note_amount, (*note).clone()))
            } else if remaining < amount {
                // we can't make exact change, so just use this note
                selected.push((note_amount, (*note).clone()));
                break;
            }
        }

        Some(selected.into_iter().collect::<TieredMulti<C>>())
    }
}

impl TieredMulti<()> {
    /// Determines the denominations to use when representing an amount
    ///
    /// Algorithm tries to leave the user with a target number of
    /// `denomination_sets` starting at the lowest denomination.  `self`
    /// gives the denominations that the user already has.
    pub fn represent_amount<K, V>(
        amount: Amount,
        current_denominations: &TieredMulti<V>,
        tiers: &Tiered<K>,
        denomination_sets: u16,
    ) -> Tiered<usize> {
        let mut remaining_amount = amount;
        let mut denominations: Tiered<usize> = Default::default();

        // try to hit the target `denomination_sets`
        for tier in tiers.tiers() {
            let notes = current_denominations
                .get(*tier)
                .map(|v| v.len())
                .unwrap_or(0);
            let missing_notes = (denomination_sets as u64).saturating_sub(notes as u64);
            let possible_notes = remaining_amount / *tier;

            let add_notes = min(possible_notes, missing_notes);
            *denominations.get_mut_or_default(*tier) = add_notes as usize;
            remaining_amount -= *tier * add_notes;
        }

        // if there is a remaining amount, add denominations with a greedy algorithm
        for tier in tiers.tiers().rev() {
            let res = remaining_amount / *tier;
            remaining_amount %= *tier;
            *denominations.get_mut_or_default(*tier) += res as usize;
        }

        let represented: u64 = denominations
            .iter()
            .map(|(k, v)| k.msats * (*v as u64))
            .sum();
        assert_eq!(represented, amount.msats);
        denominations
    }
}

impl<C> FromIterator<(Amount, C)> for TieredMulti<C> {
    fn from_iter<T: IntoIterator<Item = (Amount, C)>>(iter: T) -> Self {
        let mut res = TieredMulti::default();
        res.extend(iter);
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
            self.0.entry(amount).or_default().push(note)
        }
    }
}

impl<C> Encodable for TieredMulti<C>
where
    C: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.consensus_encode(writer)
    }
}

impl<C> Decodable for TieredMulti<C>
where
    C: Decodable,
{
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(TieredMulti(BTreeMap::consensus_decode(d, modules)?))
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
        for iter in self.iters.iter_mut() {
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

#[cfg(test)]
mod test {
    use fedimint_api::Amount;

    use crate::{Tiered, TieredMulti};

    #[test]
    fn represent_amount_targets_denomination_sets() {
        let starting = notes(vec![
            (Amount::from_sats(1), 1),
            (Amount::from_sats(2), 3),
            (Amount::from_sats(3), 2),
        ]);
        let tiers = tiers(vec![1, 2, 3, 4]);

        // target 3 tiers will fill out the 1 and 3 denominations
        assert_eq!(
            TieredMulti::represent_amount(Amount::from_sats(6), &starting, &tiers, 3),
            denominations(vec![
                (Amount::from_sats(1), 3),
                (Amount::from_sats(2), 0),
                (Amount::from_sats(3), 1),
                (Amount::from_sats(4), 0)
            ])
        );

        // target 2 tiers will fill out the 1 and 4 denominations
        assert_eq!(
            TieredMulti::represent_amount(Amount::from_sats(6), &starting, &tiers, 2),
            denominations(vec![
                (Amount::from_sats(1), 2),
                (Amount::from_sats(2), 0),
                (Amount::from_sats(3), 0),
                (Amount::from_sats(4), 1)
            ])
        );
    }

    #[test]
    fn select_notes_returns_exact_amount_with_minimum_notes() {
        let starting = notes(vec![
            (Amount::from_sats(1), 10),
            (Amount::from_sats(5), 10),
            (Amount::from_sats(20), 10),
        ]);

        assert_eq!(
            starting.select_notes(Amount::from_sats(7)),
            Some(notes(vec![
                (Amount::from_sats(1), 2),
                (Amount::from_sats(5), 1)
            ]))
        );

        assert_eq!(
            starting.select_notes(Amount::from_sats(20)),
            Some(notes(vec![(Amount::from_sats(20), 1),]))
        );
    }

    #[test]
    fn select_notes_returns_next_smallest_amount_if_exact_change_cannot_be_made() {
        let starting = notes(vec![
            (Amount::from_sats(1), 1),
            (Amount::from_sats(5), 5),
            (Amount::from_sats(20), 5),
        ]);

        assert_eq!(
            starting.select_notes(Amount::from_sats(7)),
            Some(notes(vec![(Amount::from_sats(5), 2)]))
        );
    }

    #[test]
    fn select_notes_returns_none_if_amount_is_too_large() {
        let starting = notes(vec![(Amount::from_sats(10), 1)]);

        assert_eq!(starting.select_notes(Amount::from_sats(100)), None);
    }

    #[test]
    fn select_notes_avg_test() {
        let max_amount = Amount::from_sats(1000000);
        let tiers = Tiered::gen_denominations(max_amount);
        let tiered =
            TieredMulti::represent_amount::<(), ()>(max_amount, &Default::default(), &tiers, 3);

        let mut total_notes = 0;
        for multiplier in 1..100 {
            let notes = notes(tiered.as_map().clone().into_iter().collect());
            let select = notes.select_notes(Amount::from_sats(multiplier * 1000));
            total_notes += select.unwrap().into_iter_items().count();
        }
        assert_eq!(total_notes / 100, 10);
    }

    fn notes(notes: Vec<(Amount, usize)>) -> TieredMulti<usize> {
        notes
            .into_iter()
            .flat_map(|(amount, number)| vec![(amount, 0_usize); number])
            .collect()
    }

    fn tiers(tiers: Vec<u64>) -> Tiered<()> {
        tiers
            .into_iter()
            .map(|tier| (Amount::from_sats(tier), ()))
            .collect()
    }

    fn denominations(denominations: Vec<(Amount, usize)>) -> Tiered<usize> {
        denominations.into_iter().collect()
    }
}
