use std::{cmp, fmt, ops, thread_local};

use serde_json::Value;

pub fn rust_log_full_enabled() -> bool {
    // this will be called only once per-thread for best performance
    thread_local!(static RUST_LOG_FULL: bool = {
        std::env::var_os("RUST_LOG_FULL")
            .map(|val| !val.is_empty())
            .unwrap_or(false)
    });
    RUST_LOG_FULL.with(|x| *x)
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

impl<'a> fmt::Debug for AbbreviateHexBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Use for displaying potentially large `[serde_json::Value]`s in the logs
///
/// Notably, unlike normal `fmt::Debug` for `serde_json::Value` it does not
/// respect pretty-printing and other formatting settings on the `formatter`.
/// Which for debugging & logs should be OK.
pub struct AbbreviateJson<'a>(pub &'a serde_json::Value);

// TODO: use `str::floor_char_boundary` instead (when it becomes stable)
// https://github.com/rust-lang/rust/blob/97872b792c9dd6a9bc5c3f4e62a0bd5958b09cdc/library/core/src/str/mod.rs#L258
pub fn floor_char_boundary(s: &str, index: usize) -> usize {
    // https://github.com/rust-lang/rust/blob/97872b792c9dd6a9bc5c3f4e62a0bd5958b09cdc/library/core/src/num/mod.rs#L883
    #[inline]
    pub const fn is_utf8_char_boundary(byte: u8) -> bool {
        // This is bit magic equivalent to: b < 128 || b >= 192
        (byte as i8) >= -0x40
    }

    if index >= s.len() {
        s.len()
    } else {
        let lower_bound = index.saturating_sub(3);
        let new_index = s.as_bytes()[lower_bound..=index]
            .iter()
            .rposition(|b| is_utf8_char_boundary(*b));

        // SAFETY: we know that the character boundary will be within four bytes
        unsafe { lower_bound + new_index.unwrap_unchecked() }
    }
}

/// Format json string value if it's too long
fn fmt_abbreviated_str(value: &str, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    const STRING_ABBR_LEN: usize = 128;
    fmt::Debug::fmt(
        &value[..floor_char_boundary(value, cmp::min(STRING_ABBR_LEN, value.len()))],
        formatter,
    )?;
    if STRING_ABBR_LEN < value.len() {
        formatter.write_fmt(format_args!("... {} total", value.len()))?;
    }
    Ok(())
}

/// Format json array value truncating elements if there's too many, and values
/// if they are too long
fn fmt_abbreviated_vec(vec: &[Value], formatter: &mut fmt::Formatter) -> fmt::Result {
    const ARRAY_ABBR_LEN: usize = 64;
    formatter.write_str("[")?;
    for (i, v) in vec.iter().enumerate().take(ARRAY_ABBR_LEN) {
        fmt::Debug::fmt(&AbbreviateJson(v), formatter)?;
        if i != vec.len() - 1 {
            formatter.write_str(", ")?;
        }
    }
    if ARRAY_ABBR_LEN < vec.len() {
        formatter.write_fmt(format_args!("... {} total", vec.len()))?;
    }
    formatter.write_str("]")?;
    Ok(())
}

/// Format json object value truncating keys if there's too many, and keys and
/// values if they are too long
fn fmt_abbreviated_object(
    map: &serde_json::Map<String, Value>,
    formatter: &mut fmt::Formatter,
) -> fmt::Result {
    const MAP_ABBR_LEN: usize = 64;
    formatter.write_str("{")?;
    for (i, (k, v)) in map.iter().enumerate().take(MAP_ABBR_LEN) {
        fmt_abbreviated_str(k, formatter)?;
        formatter.write_str(": ")?;
        fmt::Debug::fmt(&AbbreviateJson(v), formatter)?;
        if i != map.len() - 1 {
            formatter.write_str(", ")?;
        }
    }
    if MAP_ABBR_LEN < map.len() {
        formatter.write_fmt(format_args!("... {} total", map.len()))?;
    }
    formatter.write_str("}")?;
    Ok(())
}

impl<'a> fmt::Debug for AbbreviateJson<'a> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if rust_log_full_enabled() {
            std::fmt::Debug::fmt(&self.0, formatter)
        } else {
            // modified https://github.com/serde-rs/json/blob/e41ee42d92022dbffc00f4ed50580fa5e060a379/src/value/mod.rs#L177
            match self.0 {
                Value::Null => formatter.write_str("Null"),
                Value::Bool(boolean) => write!(formatter, "Bool({boolean})"),
                Value::Number(number) => fmt::Debug::fmt(number, formatter),
                Value::String(string) => {
                    formatter.write_str("String(")?;
                    fmt_abbreviated_str(string, formatter)?;
                    formatter.write_str(")")
                }
                Value::Array(vec) => {
                    formatter.write_str("Array ")?;
                    fmt_abbreviated_vec(vec, formatter)
                }
                Value::Object(map) => {
                    formatter.write_str("Object ")?;
                    fmt_abbreviated_object(map, formatter)
                }
            }
        }
    }
}

/// Something that can be debug-formatted in an abbreviated way
pub trait AbbreviatedDebug {
    fn abbreviated_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

/// A wrapper that causes the inner `T` to be debug-formatted using
/// [`AbbreviatedDebug`]
///
/// Useful in situations where using more specific wrapper is not feasible,
/// e.g. the value to be abbreviated is nested inside larger struct
/// where everything should be `debug-printed` together.
pub struct AbbreviateDebug<T>(pub T);

impl<T> fmt::Debug for AbbreviateDebug<T>
where
    T: AbbreviatedDebug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.abbreviated_fmt(f)
    }
}

impl<T> ops::Deref for AbbreviateDebug<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AbbreviatedDebug for serde_json::Value {
    fn abbreviated_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&AbbreviateJson(self), f)
    }
}

impl<const N: usize> AbbreviatedDebug for [u8; N] {
    fn abbreviated_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&AbbreviateHexBytes(self), f)
    }
}

impl AbbreviatedDebug for &[serde_json::Value] {
    fn abbreviated_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_abbreviated_vec(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check_abbreviate_json() {
        for v in [
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!(false),
            serde_json::json!("foo"),
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!([1]),
            serde_json::json!([1, 3, 4]),
            serde_json::json!({"a": "b"}),
            serde_json::json!({"a": "b", "c": "d"}),
            serde_json::json!({"a": { "foo": "bar"}, "c": "d"}),
            serde_json::json!({"a": [1, 2, 3, 4], "b": {"c": "d"}}),
            serde_json::json!([{"a": "b"}]),
            serde_json::json!([{"a": "b"}, {"d": "f"}]),
            serde_json::json!([null]),
        ] {
            assert_eq!(format!("{:?}", &v), format!("{:?}", AbbreviateJson(&v)));
        }
    }
}
