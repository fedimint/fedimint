//! Denomination health policy and deterministic rebalance planning.
//!
//! Offline sends spend notes without contacting the federation, so the wallet
//! can run short of small denominations. This module decides whether that has
//! happened and which denominations a rebalancing reissue should produce. It
//! performs no I/O and no randomization; scheduling belongs to the caller.

use std::collections::BTreeMap;

use fedimint_core::Amount;
use fedimint_mintv2_common::Denomination;
use fedimint_mintv2_common::config::{FeeConsensus, client_denominations};
use thiserror::Error;

use crate::SpendableNote;

/// Notes per denomination that a rebalance keeps the wallet within.
///
/// A managed denomination holding fewer than `min_notes_per_denomination`
/// notes is unhealthy. A rebalance then restores it to
/// `target_notes_per_denomination`. The gap between the two gives hysteresis,
/// so one spend that dips a denomination below the minimum does not trigger a
/// rebalance for every later note.
///
/// Only denominations up to `largest_managed_denomination` are managed. Larger
/// notes are too valuable to keep stocked, so a wallet is not unhealthy for
/// lacking them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenominationPolicy {
    /// A managed denomination with fewer notes than this is unhealthy.
    pub min_notes_per_denomination: u64,
    /// The note count a rebalance restores an unhealthy denomination to.
    pub target_notes_per_denomination: u64,
    /// Upper bound on the number of notes one rebalance transaction creates.
    pub max_notes_per_rebalance_tx: usize,
    /// The largest denomination the policy keeps stocked.
    pub largest_managed_denomination: Denomination,
}

/// Returned when a [`DenominationPolicy`] cannot be used.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum InvalidDenominationPolicy {
    /// The target is below the minimum, so a restored denomination would still
    /// be unhealthy and every rebalance would fire again.
    #[error("target ({target}) must be at least the minimum ({min})")]
    TargetBelowMinimum { min: u64, target: u64 },
    /// A rebalance transaction must be able to create at least one note.
    #[error("a rebalance transaction must create at least one note")]
    NoNotesPerTransaction,
    /// The managed range is empty, so the policy would never act.
    #[error("no client denomination is at or below {largest:?}")]
    NoManagedDenominations { largest: Denomination },
}

impl DenominationPolicy {
    /// Creates a policy, rejecting combinations that could never settle.
    pub fn new(
        min_notes_per_denomination: u64,
        target_notes_per_denomination: u64,
        max_notes_per_rebalance_tx: usize,
        largest_managed_denomination: Denomination,
    ) -> Result<Self, InvalidDenominationPolicy> {
        if target_notes_per_denomination < min_notes_per_denomination {
            return Err(InvalidDenominationPolicy::TargetBelowMinimum {
                min: min_notes_per_denomination,
                target: target_notes_per_denomination,
            });
        }

        if max_notes_per_rebalance_tx == 0 {
            return Err(InvalidDenominationPolicy::NoNotesPerTransaction);
        }

        if !client_denominations().any(|d| d <= largest_managed_denomination) {
            return Err(InvalidDenominationPolicy::NoManagedDenominations {
                largest: largest_managed_denomination,
            });
        }

        Ok(Self {
            min_notes_per_denomination,
            target_notes_per_denomination,
            max_notes_per_rebalance_tx,
            largest_managed_denomination,
        })
    }

    /// Whether `denomination` is one this policy keeps stocked.
    pub fn manages(&self, denomination: Denomination) -> bool {
        denomination <= self.largest_managed_denomination
    }

    /// The managed denominations, smallest first.
    pub fn managed_denominations(self) -> impl Iterator<Item = Denomination> {
        client_denominations().take_while(move |d| self.manages(*d))
    }

    /// Whether a managed denomination holding `count` notes is healthy.
    pub fn is_healthy(&self, count: u64) -> bool {
        count >= self.min_notes_per_denomination
    }
}

impl Default for DenominationPolicy {
    fn default() -> Self {
        Self {
            min_notes_per_denomination: 1,
            target_notes_per_denomination: 3,
            max_notes_per_rebalance_tx: 20,
            // 2^20 msats is roughly one thousand sats.
            largest_managed_denomination: Denomination(20),
        }
    }
}

/// The denominations a rebalance transaction should create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalancePlan {
    /// Denominations of the notes to create, smallest first.
    pub outputs: Vec<Denomination>,
    /// How many notes each unhealthy denomination needs to reach its target.
    pub deficit: BTreeMap<Denomination, u64>,
}

/// Plans the notes a rebalance should create, or `None` if nothing is needed
/// or nothing can be funded.
///
/// Only unhealthy denominations are topped up, and only to the policy target.
/// Denominations are funded smallest first, so when the wallet's value cannot
/// cover the full target profile the small denominations, which offline sends
/// need most, are the ones restored.
///
/// `spendable_value` is the value of the whole inventory net of the fee for
/// spending each note as an input.
pub fn plan_rebalance(
    counts: &BTreeMap<Denomination, u64>,
    spendable_value: Amount,
    fee: &FeeConsensus,
    policy: &DenominationPolicy,
) -> Option<RebalancePlan> {
    let mut budget = spendable_value;
    let mut outputs = Vec::new();
    let mut deficit = BTreeMap::new();

    for denomination in policy.managed_denominations() {
        let count = counts.get(&denomination).copied().unwrap_or(0);

        if policy.is_healthy(count) {
            continue;
        }

        let missing = policy.target_notes_per_denomination - count;
        deficit.insert(denomination, missing);

        let cost = denomination.amount() + fee.fee(denomination.amount());

        for _ in 0..missing {
            if outputs.len() >= policy.max_notes_per_rebalance_tx {
                break;
            }

            let Some(remaining) = budget.checked_sub(cost) else {
                break;
            };

            budget = remaining;
            outputs.push(denomination);
        }
    }

    (!outputs.is_empty()).then_some(RebalancePlan { outputs, deficit })
}

/// Greedily selects notes, largest first, that sum to exactly `remaining`.
///
/// The first `reserve` notes of each denomination in `notes_desc` are held
/// back, so a spend that succeeds leaves at least `reserve` notes of every
/// denomination it touched. Pass `0` to allow spending any note. Returns
/// `None` if no exact selection exists under the given reserve.
pub fn greedy_exact_change(
    notes_desc: &[SpendableNote],
    mut remaining: Amount,
    reserve: u64,
) -> Option<Vec<SpendableNote>> {
    let mut held_back: BTreeMap<Denomination, u64> = BTreeMap::new();
    let mut selected = Vec::new();

    for note in notes_desc {
        let seen = held_back.entry(note.denomination).or_insert(0);

        if *seen < reserve {
            *seen += 1;
            continue;
        }

        let Some(rest) = remaining.checked_sub(note.amount()) else {
            continue;
        };

        remaining = rest;
        selected.push(note.clone());

        if remaining == Amount::ZERO {
            break;
        }
    }

    (remaining == Amount::ZERO).then_some(selected)
}

#[cfg(test)]
mod tests;
