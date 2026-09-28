use fedimint_core::Amount;
use lightning_invoice::RoutingFees;

use super::{ParsePaymentFeeError, PaymentFee};

/// A lower `base` must not let an over-limit `parts_per_million` through,
/// which is what the lexicographic ordering used to allow.
#[test]
fn is_within_enforces_both_components() {
    // base under the limit, ppm over it, on the send side.
    let over_ppm = PaymentFee {
        base: Amount::from_sats(0),
        parts_per_million: 1_000_000,
    };
    assert!(!over_ppm.is_within(&PaymentFee::SEND_FEE_LIMIT));

    let over_ppm = PaymentFee {
        base: Amount::from_sats(0),
        parts_per_million: 5_000_000,
    };
    assert!(!over_ppm.is_within(&PaymentFee::SEND_FEE_LIMIT));

    // Same on the receive side, which has the lower cap of the two.
    let over_ppm = PaymentFee {
        base: Amount::from_sats(0),
        parts_per_million: 500_000,
    };
    assert!(!over_ppm.is_within(&PaymentFee::RECEIVE_FEE_LIMIT));

    // The reverse case, which the ordering already rejected.
    let over_base = PaymentFee {
        base: Amount::from_sats(101),
        parts_per_million: 0,
    };
    assert!(!over_base.is_within(&PaymentFee::SEND_FEE_LIMIT));

    // Exactly at the limit is accepted.
    assert!(PaymentFee::SEND_FEE_LIMIT.is_within(&PaymentFee::SEND_FEE_LIMIT));

    // Strictly within on both components is accepted.
    let ok = PaymentFee {
        base: Amount::from_sats(50),
        parts_per_million: 10_000,
    };
    assert!(ok.is_within(&PaymentFee::SEND_FEE_LIMIT));
}

/// Adding two operator-supplied fees must not panic on overflow, in either
/// component.
#[test]
fn checked_add_reports_overflow_instead_of_panicking() {
    let max_base = PaymentFee {
        base: Amount::from_msats(u64::MAX),
        parts_per_million: 0,
    };
    let one_msat = PaymentFee {
        base: Amount::from_msats(1),
        parts_per_million: 0,
    };
    assert!(max_base.checked_add(one_msat).is_none());

    let max_ppm = PaymentFee {
        base: Amount::ZERO,
        parts_per_million: u64::MAX,
    };
    let one_ppm = PaymentFee {
        base: Amount::ZERO,
        parts_per_million: 1,
    };
    assert!(max_ppm.checked_add(one_ppm).is_none());

    assert_eq!(
        PaymentFee::TRANSACTION_FEE_DEFAULT
            .checked_add(PaymentFee::TRANSACTION_FEE_DEFAULT)
            .expect("Two default fees fit"),
        PaymentFee {
            base: Amount::from_sats(4),
            parts_per_million: 6_000,
        }
    );
}

/// A fee that outgrew the `u32`s of `RoutingFees` must surface as an error
/// rather than a panic: the conversion runs on every lightning payment and
/// on federation registration at startup, so a panic here boot-loops the
/// gateway.
#[test]
fn routing_fees_conversion_rejects_out_of_range_fees() {
    let over_base = PaymentFee {
        base: Amount::from_msats(u64::from(u32::MAX) + 1),
        parts_per_million: 0,
    };
    assert!(RoutingFees::try_from(over_base).is_err());

    let over_ppm = PaymentFee {
        base: Amount::ZERO,
        parts_per_million: u64::from(u32::MAX) + 1,
    };
    assert!(RoutingFees::try_from(over_ppm).is_err());

    let fees = RoutingFees::try_from(PaymentFee::SEND_FEE_LIMIT)
        .expect("The send fee limit is within range");
    assert_eq!(fees.base_msat, 100_000);
    assert_eq!(fees.proportional_millionths, 15_000);
}

/// Any fee that `set_fees` accepts is small enough for the fee arithmetic
/// to stay exact, and an out-of-range fee left in an old database must
/// saturate instead of panicking.
#[test]
fn absolute_fee_saturates_instead_of_panicking() {
    let huge = PaymentFee {
        base: Amount::from_msats(u64::MAX),
        parts_per_million: u64::MAX,
    };
    assert_eq!(huge.fee(u64::MAX), Amount::from_msats(u64::MAX));

    assert_eq!(
        PaymentFee::TRANSACTION_FEE_DEFAULT.fee(1_000_000),
        Amount::from_msats(2_000 + 3_000)
    );
}

/// A fee string that is not a `<base>,<ppm>` pair is one condition, not
/// three, and the operator who typed it needs to see which half of the
/// pair the parser could not read.
#[test]
fn parsing_a_fee_names_the_half_that_failed() {
    assert!(matches!(
        "1000".parse::<PaymentFee>(),
        Err(ParsePaymentFeeError::Format)
    ));
    assert!(matches!(
        "".parse::<PaymentFee>(),
        Err(ParsePaymentFeeError::Format)
    ));
    assert!(matches!(
        "1,2,3".parse::<PaymentFee>(),
        Err(ParsePaymentFeeError::Format)
    ));
    assert!(matches!(
        "banana,3000".parse::<PaymentFee>(),
        Err(ParsePaymentFeeError::Base(_))
    ));
    assert!(matches!(
        "2000,banana".parse::<PaymentFee>(),
        Err(ParsePaymentFeeError::PartsPerMillion(_))
    ));
}

/// The `Display`/`FromStr` pair is what clap uses for the gateway's
/// `--default-routing-fees` flag and its default value, so it has to round
/// trip.
#[test]
fn a_fee_round_trips_through_its_text_form() {
    let fee = PaymentFee::TRANSACTION_FEE_DEFAULT;

    assert_eq!(
        fee.to_string()
            .parse::<PaymentFee>()
            .expect("The rendered form parses back"),
        fee
    );
}
