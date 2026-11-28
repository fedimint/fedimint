use super::{counted_whole_window, volume_buckets};

#[test]
fn window_ends_before_the_unfinished_bucket() {
    // Block count 14,399 is the last block of bucket 99, so the window ends
    // with bucket 98. The window moves only when bucket 100 starts.
    assert_eq!(volume_buckets(14_399, 7), 92..99);
    assert_eq!(volume_buckets(14_400, 7), 93..100);
    assert_eq!(volume_buckets(432, 30), 0..3);
    assert_eq!(volume_buckets(143, 7), 0..0);
}

#[test]
fn completeness_excludes_the_upgrade_bucket() {
    let window = volume_buckets(14_400, 7);
    // Bucket 93 starts at block count 13,392.
    assert!(!counted_whole_window(None, window.start));
    assert!(counted_whole_window(Some(0), window.start));
    assert!(counted_whole_window(Some(13_391), window.start));
    assert!(!counted_whole_window(Some(13_392), window.start));
    assert!(!counted_whole_window(Some(13_393), window.start));
    assert!(counted_whole_window(
        Some(13_392),
        volume_buckets(14_544, 7).start
    ));

    let young = volume_buckets(432, 7);
    assert!(counted_whole_window(Some(0), young.start));
    assert!(!counted_whole_window(Some(1), young.start));
}
