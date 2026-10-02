use super::{Amount, TieredMulti};

#[test]
fn summary_works() {
    let notes = TieredMulti::from_iter(vec![
        (Amount::from_sats(1), ()),
        (Amount::from_sats(2), ()),
        (Amount::from_sats(3), ()),
        (Amount::from_sats(3), ()),
        (Amount::from_sats(2), ()),
        (Amount::from_sats(2), ()),
    ]);
    let summary = notes.summary();
    assert_eq!(
        summary.iter().collect::<Vec<_>>(),
        vec![
            (Amount::from_sats(1), 1),
            (Amount::from_sats(2), 3),
            (Amount::from_sats(3), 2),
        ]
    );
    assert_eq!(summary.total_amount(), notes.total_amount());
    assert_eq!(summary.count_items(), notes.count_items());
    assert_eq!(summary.count_tiers(), notes.count_tiers());
}

#[test]
fn total_amount_saturates_on_overflow() {
    // Tier value times note count overflows
    let notes = TieredMulti::from_iter(vec![
        (Amount::from_msats(u64::MAX / 2 + 1), ()),
        (Amount::from_msats(u64::MAX / 2 + 1), ()),
    ]);
    assert_eq!(notes.count_tiers(), 1);
    assert_eq!(notes.checked_total_amount(), None);
    assert_eq!(notes.total_amount(), Amount::from_msats(u64::MAX));

    // Sum across tiers overflows
    let notes = TieredMulti::from_iter(vec![
        (Amount::from_msats(u64::MAX - 1), ()),
        (Amount::from_msats(2), ()),
    ]);
    assert_eq!(notes.checked_total_amount(), None);
    assert_eq!(notes.total_amount(), Amount::from_msats(u64::MAX));

    // Exactly `u64::MAX` does not overflow
    let notes = TieredMulti::from_iter(vec![
        (Amount::from_msats(u64::MAX - 1), ()),
        (Amount::from_msats(1), ()),
    ]);
    assert_eq!(
        notes.checked_total_amount(),
        Some(Amount::from_msats(u64::MAX))
    );
}
