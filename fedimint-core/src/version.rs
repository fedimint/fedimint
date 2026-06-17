/// Get the  cargo package version of `fedimint-core`
pub fn cargo_pkg() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get the `x.y.z` cargo release version of `fedimint-core`.
pub fn cargo_pkg_release() -> &'static str {
    release_version(cargo_pkg())
}

/// Return only the `x.y.z` release component of a cargo package version.
pub fn release_version(version: &str) -> &str {
    version
        .split(['-', '+'])
        .next()
        .expect("split always returns at least one item")
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

/// Returns the version hash if it is meaningful (i.e. not all zeros, which
/// `fedimint-build` substitutes when no git information is available).
pub fn non_zero_version_hash(hash: &str) -> Option<&str> {
    if hash.bytes().all(|b| b == b'0') {
        None
    } else {
        Some(hash)
    }
}

#[cfg(test)]
mod tests;
