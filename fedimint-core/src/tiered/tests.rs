use fedimint_core::Amount;

use super::Tiered;

#[test]
fn tier_generation_including_max_amount() {
    let max_amount = Amount::from_msats(16);
    let denominations = Tiered::gen_denominations(2, max_amount);

    // should produce [1, 2, 4, 8, 16]
    assert_eq!(denominations.tiers().count(), 5);
}

#[test]
fn tier_generation_base_10() {
    let max_amount = Amount::from_msats(10000);
    let denominations = Tiered::gen_denominations(10, max_amount);

    // should produce [1, 10, 100, 1000, 10_000]
    assert_eq!(denominations.tiers().count(), 5);
}

#[test]
fn test_gen_denominations_invalid_bases() {
    let max_amount = Amount::from_msats(1000);
    assert_eq!(Tiered::gen_denominations(0, max_amount).tiers().count(), 0);
    assert_eq!(Tiered::gen_denominations(1, max_amount).tiers().count(), 0);
}

#[test]
fn test_gen_denominations_max_u64_does_not_overflow() {
    let max_amount = Amount::from_msats(u64::MAX);
    let denominations = Tiered::gen_denominations(2, max_amount);
    // Base 2 powers from 2^0 to 2^63 => 64 tiers
    assert_eq!(denominations.tiers().count(), 64);
}

