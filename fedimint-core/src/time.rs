// nosemgrep: ban-system-time-now
use std::time::SystemTime;

#[cfg(not(target_family = "wasm"))]
pub fn now() -> SystemTime {
    // nosemgrep: ban-system-time-now
    SystemTime::now()
}

#[cfg(target_family = "wasm")]
pub fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        + std::time::Duration::from_secs_f64(js_sys::Date::new_0().get_time() / 1000.)
}

/// Returns the duration since the Unix epoch
pub fn duration_since_epoch() -> std::time::Duration {
    now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time to work")
}
