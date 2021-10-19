use minimint_api::transaction::{Input, Transaction};
use minimint_api::{Coin, Coins, PegInProof};
use std::collections::HashSet;

pub trait ConflictFilterable<T>
where
    Self: Iterator<Item = T> + Sized,
{
    fn filter_conflicts<F>(self, map: F) -> ConflictFilter<Self, T, F>
    where
        F: Fn(&T) -> &Transaction;
}

pub struct ConflictFilter<I, T, F>
where
    I: Iterator<Item = T>,
    F: Fn(&T) -> &Transaction,
{
    inner_iter: I,
    tx_accessor: F,
    coin_set: HashSet<Coins<Coin>>,
    peg_in_set: HashSet<PegInProof>,
}

impl<I, T> ConflictFilterable<T> for I
where
    I: Iterator<Item = T>,
{
    fn filter_conflicts<F>(self, tx_accessor: F) -> ConflictFilter<Self, T, F>
    where
        F: Fn(&T) -> &Transaction,
    {
        ConflictFilter {
            inner_iter: self,
            tx_accessor,
            coin_set: Default::default(),
            peg_in_set: Default::default(),
        }
    }
}

impl<I, T, F> Iterator for ConflictFilter<I, T, F>
where
    I: Iterator<Item = T>,
    F: Fn(&T) -> &Transaction,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.inner_iter.next()?;
        let tx = (self.tx_accessor)(&next);
        for input in &tx.inputs {
            match input {
                Input::Coins(ref coins) => {
                    // TODO: can this be done without cloning? E.g. hashing?
                    if !self.coin_set.insert(coins.clone()) {
                        return None;
                    }
                }
                Input::PegIn(ref peg_in) => {
                    if !self.peg_in_set.insert(peg_in.as_ref().clone()) {
                        return None;
                    }
                }
            }
        }
        Some(next)
    }
}
