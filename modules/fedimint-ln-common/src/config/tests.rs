use fedimint_core::{Amount, msats};
use lightning_invoice::RoutingFees;

use super::FeeToAmount;

fn fees(base_msat: u32, proportional_millionths: u32) -> RoutingFees {
    RoutingFees {
        base_msat,
        proportional_millionths,
    }
}

/// `LNv1`'s deployed fee formula divides by a truncated divisor. Keep those
/// values stable while making the pathological divisor non-panicking.
#[test]
fn margin_uses_legacy_truncated_divisor() {
    assert_eq!(fees(0, 100).to_amount(&msats(1_000_000)), msats(100));
    assert_eq!(fees(0, 3_000).to_amount(&msats(1_000_000)), msats(3_003));
    assert_eq!(
        fees(0, 600_000).to_amount(&msats(1_000_000)),
        msats(1_000_000)
    );
    assert_eq!(
        fees(0, 1_000_000).to_amount(&msats(1_000_000)),
        msats(1_000_000)
    );
}

#[test]
fn base_fee_is_added_to_the_margin() {
    assert_eq!(fees(500, 0).to_amount(&msats(1_000_000)), msats(500));
    assert_eq!(fees(500, 100).to_amount(&msats(1_000_000)), msats(600));
    assert_eq!(fees(500, 0).to_amount(&Amount::ZERO), msats(500));
}

/// A rate above one million used to make `1_000_000 / rate` truncate to zero,
/// and the division by it panicked. Price it out of range instead.
#[test]
fn rate_above_one_million_prices_out_of_range_rather_than_panicking() {
    assert_eq!(
        fees(0, 1_000_001).to_amount(&msats(1_000_000)),
        msats(u64::MAX)
    );
    assert_eq!(
        fees(0, u32::MAX).to_amount(&msats(1_000_000)),
        msats(u64::MAX)
    );
}

#[test]
fn base_fee_addition_saturates() {
    assert_eq!(
        fees(u32::MAX, 1_000_000).to_amount(&msats(u64::MAX)),
        msats(u64::MAX)
    );
}
