use bitcoin::Amount;

use super::VolumeBucket;

#[test]
fn volume_totals_saturate_each_direction_independently() {
    let mut bucket = VolumeBucket {
        deposited: Amount::from_sat(u64::MAX - 1),
        withdrawn: Amount::from_sat(7),
    };
    bucket.accumulate(VolumeBucket {
        deposited: Amount::from_sat(3),
        withdrawn: Amount::from_sat(11),
    });
    assert_eq!(bucket.deposited, Amount::from_sat(u64::MAX));
    assert_eq!(bucket.withdrawn, Amount::from_sat(18));
    bucket.accumulate(VolumeBucket {
        deposited: Amount::ZERO,
        withdrawn: Amount::from_sat(u64::MAX),
    });
    assert_eq!(bucket.withdrawn, Amount::from_sat(u64::MAX));
}
