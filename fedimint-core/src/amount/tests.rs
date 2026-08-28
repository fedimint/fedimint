use super::{Amount, AmountConversionError, FromStr};

#[test]
fn amount_multiplication_by_scalar() {
    assert_eq!(Amount::from_msats(1000) * 123, Amount::from_msats(123_000));
}

#[test]
fn scalar_multiplication_by_amount() {
    assert_eq!(123 * Amount::from_msats(1000), Amount::from_msats(123_000));
}

#[test]
fn checked_mul_success() {
    assert_eq!(
        Amount::from_msats(100).checked_mul(5),
        Some(Amount::from_msats(500))
    );
}

#[test]
fn checked_mul_overflow() {
    assert_eq!(Amount::from_msats(u64::MAX).checked_mul(2), None);
    assert_eq!(Amount::from_msats(u64::MAX / 2 + 1).checked_mul(2), None);
}

#[test]
fn test_amount_parsing() {
    // msats
    assert_eq!(Amount::from_msats(123), Amount::from_str("123").unwrap());
    assert_eq!(
        Amount::from_msats(123),
        Amount::from_str("123msat").unwrap()
    );
    assert_eq!(
        Amount::from_msats(123),
        Amount::from_str("123 msat").unwrap()
    );
    assert_eq!(
        Amount::from_msats(123),
        Amount::from_str("123 msats").unwrap()
    );
    // sats
    assert_eq!(Amount::from_sats(123), Amount::from_str("123sat").unwrap());
    assert_eq!(Amount::from_sats(123), Amount::from_str("123 sat").unwrap());
    assert_eq!(
        Amount::from_sats(123),
        Amount::from_str("123satoshi").unwrap()
    );
    assert_eq!(
        Amount::from_sats(123),
        Amount::from_str("123satoshis").unwrap()
    );
    // btc
    assert_eq!(
        Amount::from_bitcoins(123),
        Amount::from_str("123btc").unwrap()
    );
    assert_eq!(
        Amount::from_sats(12_345_600_000),
        Amount::from_str("123.456btc").unwrap()
    );
}

#[test]
fn try_into_sats_rejects_sub_satoshi_precision() {
    assert_eq!(
        Amount::from_msats(1500).try_into_sats(),
        Err(AmountConversionError::SubSatoshiPrecision { msats: 1500 })
    );
    assert_eq!(Amount::from_msats(2000).try_into_sats(), Ok(2));
}

#[test]
fn bitcoin_amount_conversion_rejects_sub_satoshi_precision() {
    assert_eq!(
        bitcoin::Amount::try_from(Amount::from_msats(1)),
        Err(AmountConversionError::SubSatoshiPrecision { msats: 1 })
    );
    assert_eq!(
        bitcoin::Amount::try_from(Amount::from_msats(1000)),
        Ok(bitcoin::Amount::from_sat(1))
    );
}
