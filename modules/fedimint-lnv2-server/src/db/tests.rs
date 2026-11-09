use fedimint_core::Amount;

use super::VolumeDay;

#[test]
fn volume_totals_saturate_each_direction_independently() {
    let mut day = VolumeDay {
        received: Amount::from_msats(u64::MAX - 1),
        sent: Amount::from_msats(7),
    };
    day.accumulate(VolumeDay {
        received: Amount::from_msats(3),
        sent: Amount::from_msats(11),
    });
    assert_eq!(day.received, Amount::from_msats(u64::MAX));
    assert_eq!(day.sent, Amount::from_msats(18));
    day.accumulate(VolumeDay {
        received: Amount::ZERO,
        sent: Amount::from_msats(u64::MAX),
    });
    assert_eq!(day.sent, Amount::from_msats(u64::MAX));
}
