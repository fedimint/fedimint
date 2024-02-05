/// Env variable to set to force git hash during build process
pub const FORCE_GIT_HASH_ENV: &str = "FEDIMINT_BUILD_FORCE_GIT_HASH";

/// Env variable the cargo will set during crate build to pass the detected git
/// hash to the binary itself.
// Note: Keep in sync with `fedimint_core::envs`, which is not reused-to avoid
// introducing extra dependencies between core and build modules.
pub const FEDIMINT_BUILD_CODE_VERSION_ENV: &str = "FEDIMINT_BUILD_CODE_VERSION";
