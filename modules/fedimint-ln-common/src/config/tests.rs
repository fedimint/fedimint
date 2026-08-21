use fedimint_core::{Amount, msats};
use lightning_invoice::RoutingFees;

use super::FeeToAmount;

fn fees(base_msat: u32, proportional_millionths: u32) -> RoutingFees {
    RoutingFees {
        base_msat,
        proportional_millionths,
    }
}

#[test]
fn fee_is_the_stated_fraction_of_the_payment() {
    assert_eq!(fees(0, 100).to_amount(&msats(1_000_000)), msats(100));
    assert_eq!(fees(0, 3_000).to_amount(&msats(1_000_000)), msats(3_000));
    assert_eq!(
        fees(0, 600_000).to_amount(&msats(1_000_000)),
        msats(600_000)
    );
}

/// The legacy form truncates the divisor before dividing, so it charges more
/// than the rate names. These numbers are what deployed clients fund, so
/// changing them breaks those clients against every gateway.
#[test]
fn legacy_fee_uses_the_truncated_divisor() {
    // 100 divides 1_000_000 exactly, so the two forms agree.
    assert_eq!(fees(0, 100).to_amount_legacy(&msats(1_000_000)), msats(100));

    // 3_000 does not: `1_000_000 / 3_000` truncates 333.33 to 333, billing the
    // stated 0.3% as 0.3003%. This is the gateway default fee.
    assert_eq!(
        fees(0, 3_000).to_amount_legacy(&msats(1_000_000)),
        msats(3_003)
    );

    // Above 500_000 the divisor truncates to 1, a flat one hundred percent.
    assert_eq!(
        fees(0, 600_000).to_amount_legacy(&msats(1_000_000)),
        msats(1_000_000)
    );
}

/// The whole rollout rests on this: a gateway validating with `to_amount`
/// accepts a contract funded with either form, so clients can move off
/// `to_amount_legacy` one at a time.
#[test]
fn corrected_fee_never_exceeds_the_legacy_fee() {
    let rates = [
        0,
        1,
        100,
        999,
        3_000,
        10_000,
        15_000,
        499_999,
        500_001,
        999_999,
        1_000_000,
        1_000_001,
        u32::MAX,
    ];
    let payments = [
        0,
        1,
        333,
        1_000,
        333_000,
        1_000_000,
        21_000_000_000,
        u64::MAX,
    ];

    for rate in rates {
        for payment in payments {
            let fees = fees(7, rate);
            let payment = msats(payment);

            assert!(
                fees.to_amount(&payment) <= fees.to_amount_legacy(&payment),
                "rate {rate} at {payment}: corrected {} exceeds legacy {}",
                fees.to_amount(&payment),
                fees.to_amount_legacy(&payment),
            );
        }
    }
}

/// A rate above one million used to make `1_000_000 / rate` truncate to zero,
/// and the division by it panicked. The value reaches this code straight off
/// the wire, so it has to price instead of panic.
#[test]
fn rate_above_one_million_does_not_panic() {
    assert_eq!(
        fees(0, 1_000_001).to_amount(&msats(1_000_000)),
        msats(1_000_001)
    );
    assert_eq!(
        fees(0, u32::MAX).to_amount(&msats(1_000_000)),
        msats(u64::from(u32::MAX))
    );

    // The legacy form has no representable divisor here, so it prices out of
    // range rather than guessing at an amount deployed clients never funded.
    assert_eq!(
        fees(0, 1_000_001).to_amount_legacy(&msats(1_000_000)),
        msats(u64::MAX)
    );
}

#[test]
fn base_fee_is_added_to_the_margin() {
    assert_eq!(fees(500, 0).to_amount(&msats(1_000_000)), msats(500));
    assert_eq!(fees(500, 100).to_amount(&msats(1_000_000)), msats(600));
    assert_eq!(fees(500, 0).to_amount(&Amount::ZERO), msats(500));

    assert_eq!(fees(500, 0).to_amount_legacy(&msats(1_000_000)), msats(500));
    assert_eq!(
        fees(500, 100).to_amount_legacy(&msats(1_000_000)),
        msats(600)
    );
}

/// Neither the margin nor the base fee added to it may overflow `u64`.
#[test]
fn absurd_fees_saturate_rather_than_overflow() {
    assert_eq!(
        fees(u32::MAX, u32::MAX).to_amount(&msats(u64::MAX)),
        msats(u64::MAX)
    );
    assert_eq!(
        fees(u32::MAX, u32::MAX).to_amount_legacy(&msats(u64::MAX)),
        msats(u64::MAX)
    );

    // The margin alone fits, but adding the base fee to it does not.
    assert_eq!(
        fees(u32::MAX, 1_000_000).to_amount(&msats(u64::MAX)),
        msats(u64::MAX)
    );
    assert_eq!(
        fees(u32::MAX, 1_000_000).to_amount_legacy(&msats(u64::MAX)),
        msats(u64::MAX)
    );
}
