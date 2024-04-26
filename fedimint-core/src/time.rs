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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duration_since_epoch() {
        let duration = duration_since_epoch();
        assert!(
            duration.as_secs() > 0,
            "Duration since epoch should be positive"
        );
    }

    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn test_now_on_non_wasm() {
        let system_time = now();
        assert!(system_time.elapsed().is_ok(), "SystemTime should be valid");
    }

    #[test]
    #[cfg(target_family = "wasm")]
    fn test_now_on_wasm() {
        let system_time = now();
        assert_eq!(
            system_time,
            SystemTime::UNIX_EPOCH,
            "SystemTime on wasm should be UNIX_EPOCH"
        );
    }
}
