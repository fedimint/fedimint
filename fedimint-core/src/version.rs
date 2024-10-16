/// Get the  cargo package version of `fedimint-core`
pub fn cargo_pkg() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get the git hash version of `fedimint-core`
///
/// Note, in certain situations this not be accurate (eg. might be all `0`s).
///
/// The return value was injected via `fedimint-build` crate at the compile
/// time.
pub fn git_hash() -> &'static str {
    option_env!("FEDIMINT_BUILD_CODE_VERSION").unwrap_or("0000000000000000000000000000000000000001")
}
