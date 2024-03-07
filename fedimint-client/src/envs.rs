use std::str::FromStr;
use std::time::Duration;

use tracing::warn;

pub const FM_DISCOVER_API_VERSION_TIMEOUT_ENV: &str = "FM_DISCOVER_API_VERSION_TIMEOUT";

#[cfg(not(target_family = "wasm"))]
pub fn get_discover_api_version_timeout() -> Duration {
    if let Ok(s) = std::env::var(FM_DISCOVER_API_VERSION_TIMEOUT_ENV) {
        match FromStr::from_str(&s) {
            Ok(secs) => return Duration::from_secs(secs),
            Err(err) => warn!(
                %err,
                var = FM_DISCOVER_API_VERSION_TIMEOUT_ENV,
                "Could not parse env variable"
            ),
        }
    }
    Duration::from_secs(60)
}

#[cfg(target_family = "wasm")]
pub fn get_discover_api_version_timeout() -> Duration {
    Duration::from_secs(60)
}
