use super::{Amount, FromStr};

#[test]
fn amount_multiplication_by_scalar() {
    assert_eq!(Amount::from_msats(1000) * 123, Amount::from_msats(123_000));
}

#[test]
fn scalar_multiplication_by_amount() {
    assert_eq!(123 * Amount::from_msats(1000), Amount::from_msats(123_000));
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
