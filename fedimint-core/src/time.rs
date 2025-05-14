use n0_future::time::SystemTime;

pub fn now() -> SystemTime {
    SystemTime::now()
}

/// Returns the duration since the Unix epoch
pub fn duration_since_epoch() -> std::time::Duration {
    now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time to work")
}
