use std::env;
use std::ffi::OsStr;

/// Safe wrapper around `env::set_var`.
/// test-runner uses a single-threaded runtime.
pub fn set_env(key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
    unsafe { env::set_var(key, value) }
}
