use super::{BitcoinAmountOrAll, Feerate, FromStr, bitcoin, weight_to_vbytes};

#[test]
fn converts_weight_to_vbytes() {
    assert_eq!(1, weight_to_vbytes(4));
    assert_eq!(2, weight_to_vbytes(5));
}

#[test]
fn calculate_fee() {
    let feerate = Feerate { sats_per_kvb: 1000 };
    assert_eq!(bitcoin::Amount::from_sat(25), feerate.calculate_fee(100));
    assert_eq!(bitcoin::Amount::from_sat(26), feerate.calculate_fee(101));
}

#[test]
fn test_deserialize_amount_or_all() {
    let all: BitcoinAmountOrAll = serde_json::from_str("\"all\"").unwrap();
    assert_eq!(all, BitcoinAmountOrAll::All);

    let amount: BitcoinAmountOrAll = serde_json::from_str("12345").unwrap();
    assert_eq!(
        amount,
        BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(12345))
    );

    let all_string = all.to_string();
    assert_eq!(all_string, "all");
    let amount_string = amount.to_string();
    assert_eq!(amount_string, "0.00012345 BTC");
    let all_parsed = BitcoinAmountOrAll::from_str(&all_string).unwrap();
    assert_eq!(all, all_parsed);
    let amount_parsed = BitcoinAmountOrAll::from_str(&amount_string).unwrap();
    assert_eq!(amount, amount_parsed);
}
