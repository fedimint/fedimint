use std::cell::Cell;
use std::fmt;
use std::thread_local;

thread_local!(static RUST_LOG_FULL: Cell<bool> = Cell::new(false));

pub fn rust_log_full_enabled() -> bool {
    // this will be called only once per-thread for best performance
    RUST_LOG_FULL.with(|v| {
        let enabled = std::env::var_os("RUST_LOG_FULL")
            .map(|val| !val.is_empty())
            .unwrap_or(false);
        v.set(enabled);
        enabled
    })
}

/// Use for displaying bytes in the logs
///
/// Will truncate values longer than 64 bytes, unless `RUST_LOG_FULL`
/// environment variable is set to a non-empty value.
pub struct AbbreviateHexBytes<'a>(pub &'a [u8]);

impl<'a> fmt::Display for AbbreviateHexBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() <= 64 || rust_log_full_enabled() {
            bitcoin_hashes::hex::format_hex(self.0, f)?;
        } else {
            bitcoin_hashes::hex::format_hex(&self.0[..64], f)?;
            f.write_fmt(format_args!("-{}", self.0.len()))?;
        }
        Ok(())
    }
}
