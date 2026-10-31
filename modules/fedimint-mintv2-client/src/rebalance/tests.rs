use std::collections::BTreeMap;

use fedimint_core::Amount;
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_mintv2_common::Denomination;
use fedimint_mintv2_common::config::FeeConsensus;

use super::{
    DenominationPolicy, InvalidDenominationPolicy, greedy_exact_change, plan_rebalance,
};
use crate::SpendableNote;

fn note(denomination: u8) -> SpendableNote {
    SpendableNote {
        denomination: Denomination(denomination),
        keypair: Keypair::new(SECP256K1, &mut thread_rng()),
        signature: tbs::Signature(bls12_381::G1Affine::generator()),
    }
}

/// Only the non-configurable base fee applies, so costs stay easy to reason
/// about without a relative fee.
fn base_fee_only() -> FeeConsensus {
    FeeConsensus::new(0).expect("zero relative fee is valid")
}

/// Every client denomination holds `count` notes, except the ones overridden
/// in `overrides`.
fn counts(count: u64, overrides: &[(u8, u64)]) -> BTreeMap<Denomination, u64> {
    (9..42)
        .map(|d| {
            let override_count = overrides
                .iter()
                .find(|(denomination, _)| *denomination == d)
                .map(|(_, count)| *count);

            (Denomination(d), override_count.unwrap_or(count))
        })
        .collect()
}

#[test]
fn policy_rejects_target_below_minimum() {
    assert_eq!(
        DenominationPolicy::new(3, 2, 10, Denomination(20)),
        Err(InvalidDenominationPolicy::TargetBelowMinimum { min: 3, target: 2 })
    );
}

#[test]
fn policy_rejects_empty_transactions() {
    assert_eq!(
        DenominationPolicy::new(1, 3, 0, Denomination(20)),
        Err(InvalidDenominationPolicy::NoNotesPerTransaction)
    );
}

#[test]
fn healthy_inventory_plans_nothing() {
    let policy = DenominationPolicy::default();

    let plan = plan_rebalance(
        &counts(3, &[]),
        Amount::from_sats(1_000_000),
        &base_fee_only(),
        &policy,
    );

    assert_eq!(plan, None);
}

#[test]
fn unhealthy_denomination_is_restored_to_target() {
    let policy = DenominationPolicy::default();

    let plan = plan_rebalance(
        &counts(3, &[(10, 0)]),
        Amount::from_sats(1_000_000),
        &base_fee_only(),
        &policy,
    )
    .expect("an empty denomination needs a rebalance");

    assert_eq!(plan.outputs, vec![Denomination(10); 3]);
    assert_eq!(plan.deficit, BTreeMap::from([(Denomination(10), 3)]));
}

#[test]
fn hysteresis_only_fires_below_minimum() {
    let policy = DenominationPolicy::new(2, 4, 20, Denomination(20)).expect("valid policy");

    // Exactly at the minimum is still healthy, so no rebalance fires.
    assert_eq!(
        plan_rebalance(
            &counts(2, &[]),
            Amount::from_sats(1_000_000),
            &base_fee_only(),
            &policy,
        ),
        None,
    );

    // One below the minimum restores all the way to the target, not just the
    // minimum.
    let plan = plan_rebalance(
        &counts(2, &[(12, 1)]),
        Amount::from_sats(1_000_000),
        &base_fee_only(),
        &policy,
    )
    .expect("one note is below the minimum of two");

    assert_eq!(plan.outputs, vec![Denomination(12); 3]);
}

#[test]
fn short_funds_restore_smallest_denominations_first() {
    let policy = DenominationPolicy::default();

    // Both 2^9 and 2^20 are empty and each needs three notes, but the budget
    // only covers two notes of 2^9. The smallest denomination gets the funds.
    let fee = base_fee_only();
    let cost_per_note = Denomination(9).amount() + fee.fee(Denomination(9).amount());
    let budget = cost_per_note.mul_u64(2);

    let plan = plan_rebalance(&counts(3, &[(9, 0), (20, 0)]), budget, &fee, &policy)
    .expect("some restoration is affordable");

    assert_eq!(plan.outputs, vec![Denomination(9); 2]);
}

#[test]
fn outputs_are_capped_per_transaction() {
    let policy = DenominationPolicy::new(1, 10, 4, Denomination(20)).expect("valid policy");

    let plan = plan_rebalance(
        &counts(3, &[(9, 0), (10, 0)]),
        Amount::from_sats(1_000_000),
        &base_fee_only(),
        &policy,
    )
    .expect("an empty denomination needs a rebalance");

    assert_eq!(
        plan.outputs,
        vec![
            Denomination(9),
            Denomination(9),
            Denomination(9),
            Denomination(9)
        ]
    );
}

#[test]
fn policy_rejects_when_no_denomination_is_managed() {
    assert_eq!(
        DenominationPolicy::new(1, 3, 20, Denomination(8)),
        Err(InvalidDenominationPolicy::NoManagedDenominations {
            largest: Denomination(8),
        })
    );
}

#[test]
fn unmanaged_denominations_are_not_restored() {
    let policy = DenominationPolicy::default();

    // 2^30 is far above the managed range, so an empty 2^30 is not a shortage.
    let plan = plan_rebalance(
        &counts(3, &[(30, 0)]),
        Amount::from_sats(1_000_000),
        &base_fee_only(),
        &policy,
    );

    assert_eq!(plan, None);
}

#[test]
fn no_funds_plans_nothing() {
    let policy = DenominationPolicy::default();

    let plan = plan_rebalance(&counts(0, &[]), Amount::ZERO, &base_fee_only(), &policy);

    assert_eq!(plan, None);
}

#[test]
fn exact_change_keeps_minimum_when_possible() {
    // One 2^10 note and three 2^9 notes can make 1024 msats two ways. The
    // reserve-aware selection must pick the two 2^9 notes, which leaves the
    // only 2^10 note in place.
    let notes = vec![note(10), note(9), note(9), note(9)];

    let selected = greedy_exact_change(&notes, Amount::from_msats(1024), 1)
        .expect("two 2^9 notes make 1024 msats");

    assert_eq!(
        selected
            .iter()
            .map(|note| note.denomination)
            .collect::<Vec<_>>(),
        vec![Denomination(9), Denomination(9)],
    );
}

#[test]
fn exact_change_falls_back_to_draining_when_reserve_blocks_it() {
    // The reserve keeps the only 2^9 note, so the reserved pass cannot reach
    // 1024 msats. The unreserved pass may spend the 2^10 note instead.
    let notes = vec![note(10), note(9)];

    assert_eq!(
        greedy_exact_change(&notes, Amount::from_msats(1024), 1),
        None
    );

    let selected = greedy_exact_change(&notes, Amount::from_msats(1024), 0)
        .expect("the 2^10 note makes exact change");

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].denomination, Denomination(10));
}
