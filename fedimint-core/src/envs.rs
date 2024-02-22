// Note: Keep in sync with `fedimint_build::envs`, which is not reused-to avoid
// introducing extra dependencies between core and build modules.
pub const FEDIMINT_BUILD_CODE_VERSION_ENV: &str = "FEDIMINT_BUILD_CODE_VERSION";

/// In tests we want to routinely enable an extra unknown module to ensure
/// all client code handles correct modules that client doesn't know about.
pub const FM_USE_UNKNOWN_MODULE_ENV: &str = "FM_USE_UNKNOWN_MODULE";

/// Get value of [`FEDIMINT_BUILD_CODE_VERSION_ENV`] at compile time
#[macro_export]
macro_rules! fedimint_build_code_version_env {
    () => {
        env!("FEDIMINT_BUILD_CODE_VERSION")
    };
}
