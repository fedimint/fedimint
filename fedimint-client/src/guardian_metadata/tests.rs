use std::time::Duration;

use super::{
    INITIAL_FAILED_REFRESH_INTERVAL, MAX_FAILED_REFRESH_INTERVAL, NORMAL_REFRESH_INTERVAL,
    next_refresh_interval,
};

#[test]
fn failed_refreshes_back_off_and_success_resets_interval() {
    let mut failed_refresh_interval = INITIAL_FAILED_REFRESH_INTERVAL;

    assert_eq!(
        next_refresh_interval(false, &mut failed_refresh_interval),
        Duration::from_secs(30)
    );
    assert_eq!(
        next_refresh_interval(false, &mut failed_refresh_interval),
        Duration::from_secs(60)
    );
    assert_eq!(
        next_refresh_interval(false, &mut failed_refresh_interval),
        Duration::from_secs(120)
    );
    assert_eq!(
        next_refresh_interval(false, &mut failed_refresh_interval),
        Duration::from_secs(240)
    );
    assert_eq!(
        next_refresh_interval(false, &mut failed_refresh_interval),
        Duration::from_secs(480)
    );
    assert_eq!(
        next_refresh_interval(false, &mut failed_refresh_interval),
        MAX_FAILED_REFRESH_INTERVAL
    );
    assert_eq!(
        next_refresh_interval(false, &mut failed_refresh_interval),
        MAX_FAILED_REFRESH_INTERVAL
    );

    assert_eq!(
        next_refresh_interval(true, &mut failed_refresh_interval),
        NORMAL_REFRESH_INTERVAL
    );
    assert_eq!(failed_refresh_interval, INITIAL_FAILED_REFRESH_INTERVAL);
}
