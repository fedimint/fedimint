use super::{counted_whole_window, volume_buckets};

#[test]
fn window_moves_only_at_a_144_block_boundary() {
    let before = volume_buckets(14_399, 7);
    let after = volume_buckets(14_400, 7);
    assert_eq!(before, 93..100);
    assert_eq!(after, 94..101);
    let young = volume_buckets(432, 30);
    assert_eq!(young, 0..4);
}

#[test]
fn completeness_excludes_the_upgrade_bucket() {
    let window = volume_buckets(14_400, 7);
    // Bucket 94 starts at block count 13,536.
    assert!(!counted_whole_window(None, window.start));
    assert!(counted_whole_window(Some(0), window.start));
    assert!(counted_whole_window(Some(13_535), window.start));
    assert!(!counted_whole_window(Some(13_536), window.start));
    assert!(!counted_whole_window(Some(13_537), window.start));
    assert!(counted_whole_window(
        Some(13_536),
        volume_buckets(14_544, 7).start
    ));

    let young = volume_buckets(432, 7);
    assert!(counted_whole_window(Some(0), young.start));
    assert!(!counted_whole_window(Some(1), young.start));
}
