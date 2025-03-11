#[macro_export]
macro_rules! crit {
    ($($t:tt)*) => {
        // nosemgrep: ban-error-logging-level
        ::tracing::error!($($t)*)
    };
}
