use fedimint_core::Amount;

use super::VolumeBucket;

#[test]
fn volume_totals_saturate_each_direction_independently() {
    let mut bucket = VolumeBucket {
        received: Amount::from_msats(u64::MAX - 1),
        sent: Amount::from_msats(7),
    };
    bucket.accumulate(VolumeBucket {
        received: Amount::from_msats(3),
        sent: Amount::from_msats(11),
    });
    assert_eq!(bucket.received, Amount::from_msats(u64::MAX));
    assert_eq!(bucket.sent, Amount::from_msats(18));
    bucket.accumulate(VolumeBucket {
        received: Amount::ZERO,
        sent: Amount::from_msats(u64::MAX),
    });
    assert_eq!(bucket.sent, Amount::from_msats(u64::MAX));
}
