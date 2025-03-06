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
