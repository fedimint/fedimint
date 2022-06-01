use crate::transaction::{Input, Output, Transaction};
use minimint_ln::contracts::{ContractId, IdentifyableContract};
use minimint_ln::ContractOrOfferOutput;
use minimint_mint::tiered::coins::Coins;
use minimint_mint::Coin;
use minimint_wallet::txoproof::PegInProof;
use std::collections::HashSet;

pub trait ConflictFilterable<T>
where
    Self: Iterator<Item = T> + Sized,
{
    fn filter_conflicts<F>(self, map: F) -> ConflictFilter<Self, T, F>
    where
        F: Fn(&T) -> &Transaction;
}

/// The conflict filter is used to ensure that no conflicting transactions are processed in the main
/// loop. If the processing happened sequentially this wouldn't be a problem, but currently it is
/// done in parallel due to computation intensive operations. This means any conflict could lead to
/// inconsistent outcomes depending on task scheduling.
pub struct ConflictFilter<I, T, F>
where
    I: Iterator<Item = T>,
    F: Fn(&T) -> &Transaction,
{
    inner_iter: I,
    tx_accessor: F,
    coin_set: HashSet<Coins<Coin>>,
    peg_in_set: HashSet<PegInProof>,
    contract_set: HashSet<ContractId>,
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
            contract_set: Default::default(),
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
                Input::Mint(ref coins) => {
                    // TODO: can this be done without cloning? E.g. hashing?
                    if !self.coin_set.insert(coins.clone()) {
                        return None;
                    }
                }
                Input::Wallet(ref peg_in) => {
                    if !self.peg_in_set.insert(peg_in.as_ref().clone()) {
                        return None;
                    }
                }
                Input::LN(input) => {
                    if !self.contract_set.insert(input.contract_id) {
                        return None;
                    }
                }
            }
        }
        for output in &tx.outputs {
            if let Output::LN(ContractOrOfferOutput::Contract(contract_output)) = output {
                // For contracts we need to avoid any parallel updating, so outputs need to
                // be tracked too. Once the main loop gets refactored such that only computation
                // intensive operations are parallelized, this restriction can be lifted.
                if !self
                    .contract_set
                    .insert(contract_output.contract.contract_id())
                {
                    return None;
                }
            }
        }
        Some(next)
    }
}
