use super::VolumeWindow;

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

#[test]
fn volume_window_ends_with_the_current_day() {
    let window = VolumeWindow::new(100, 7);
    assert_eq!((window.first_day, window.end_day), (94, 101));

    // A window longer than the clock's history starts at day zero.
    let window = VolumeWindow::new(3, 7);
    assert_eq!((window.first_day, window.end_day), (0, 4));
}

#[test]
fn volume_window_is_complete_only_if_counting_covered_it() {
    let window = VolumeWindow::new(100, 7);
    let first_second = 94 * SECONDS_PER_DAY;

    assert!(!window.is_complete(None, SECONDS_PER_DAY));
    assert!(window.is_complete(Some(0), SECONDS_PER_DAY));
    assert!(window.is_complete(Some(first_second - 1), SECONDS_PER_DAY));
    // An upgrade can leave flows uncounted at the very clock value counting
    // started at, so starting at the first day's first second is not enough.
    assert!(!window.is_complete(Some(first_second), SECONDS_PER_DAY));
    assert!(!window.is_complete(Some(first_second + 1), SECONDS_PER_DAY));
    // The next day's window no longer includes the day counting started on.
    assert!(VolumeWindow::new(101, 7).is_complete(Some(first_second), SECONDS_PER_DAY));

    // A young federation's window reaches back to day zero, so only
    // counting since formation covers it.
    let young = VolumeWindow::new(3, 7);
    assert!(young.is_complete(Some(0), SECONDS_PER_DAY));
    assert!(!young.is_complete(Some(1), SECONDS_PER_DAY));
}
