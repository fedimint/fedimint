use fedimint_core::{Amount, msats};
use lightning_invoice::RoutingFees;

use super::FeeToAmount;

fn fees(base_msat: u32, proportional_millionths: u32) -> RoutingFees {
    RoutingFees {
        base_msat,
        proportional_millionths,
    }
}

/// A rate above one million used to make `1_000_000 / rate` truncate to zero,
/// and the division by it panicked. The value reaches this code straight off
/// the wire, so it has to price instead of panic — and it prices out of range,
/// because a fee larger than the payment is one no caller should fund.
#[test]
fn rate_above_one_million_prices_out_of_range_rather_than_panicking() {
    assert_eq!(
        fees(0, 1_000_001).to_amount(&msats(1_000_000)),
        msats(u64::MAX)
    );

    // The whole range that used to panic, including its top end.
    assert_eq!(
        fees(0, u32::MAX).to_amount(&msats(1_000_000)),
        msats(u64::MAX)
    );
}

/// The rate is applied through a truncated divisor, which is what every
/// deployed LNv1 gateway validates against. Changing these numbers changes
/// what a client must fund, so it cannot be done without a rollout plan.
#[test]
fn margin_uses_the_truncated_divisor() {
    // 100 divides 1_000_000 exactly: 0.01% of 1_000_000 msat, as named.
    assert_eq!(fees(0, 100).to_amount(&msats(1_000_000)), msats(100));

    // 3_000 does not: `1_000_000 / 3_000` truncates 333.33 to 333, so the
    // stated 0.3% is billed as 0.3003%. This is the gateway default fee.
    assert_eq!(fees(0, 3_000).to_amount(&msats(1_000_000)), msats(3_003));

    // Above 500_000 the divisor truncates to 1, a flat one hundred percent.
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

/// Neither the margin nor the base fee added to it may overflow `u64`.
#[test]
fn absurd_fees_saturate_rather_than_overflow() {
    assert_eq!(
        fees(u32::MAX, u32::MAX).to_amount(&msats(u64::MAX)),
        msats(u64::MAX)
    );

    // The margin alone fits, but adding the base fee to it does not.
    assert_eq!(
        fees(u32::MAX, 1_000_000).to_amount(&msats(u64::MAX)),
        msats(u64::MAX)
    );
}
