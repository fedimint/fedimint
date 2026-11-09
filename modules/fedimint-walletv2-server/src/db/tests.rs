use bitcoin::Amount;

use super::VolumeDay;

#[test]
fn volume_totals_saturate_each_direction_independently() {
    let mut day = VolumeDay {
        deposited: Amount::from_sat(u64::MAX - 1),
        withdrawn: Amount::from_sat(7),
    };
    day.accumulate(VolumeDay {
        deposited: Amount::from_sat(3),
        withdrawn: Amount::from_sat(11),
    });
    assert_eq!(day.deposited, Amount::from_sat(u64::MAX));
    assert_eq!(day.withdrawn, Amount::from_sat(18));
    day.accumulate(VolumeDay {
        deposited: Amount::ZERO,
        withdrawn: Amount::from_sat(u64::MAX),
    });
    assert_eq!(day.withdrawn, Amount::from_sat(u64::MAX));
}
