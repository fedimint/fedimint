use std::env;

use anyhow::Context;
use fedimint_core::util::SafeUrl;
use fedimint_derive::{Decodable, Encodable};
use fedimint_logging::LOG_CORE;
use jsonrpsee_core::Serialize;
use serde::Deserialize;
use tracing::warn;

// Note: Keep in sync with `fedimint_build::envs`, which is not reused-to avoid
// introducing extra dependencies between core and build modules.
pub const FEDIMINT_BUILD_CODE_VERSION_ENV: &str = "FEDIMINT_BUILD_CODE_VERSION";

/// In tests we want to routinely enable an extra unknown module to ensure
/// all client code handles correct modules that client doesn't know about.
pub const FM_USE_UNKNOWN_MODULE_ENV: &str = "FM_USE_UNKNOWN_MODULE";

/// Check if env variable is set and not equal `0` or `false` which are common
/// ways to disable something.
pub fn is_env_var_set(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| v != "0" && v != "false")
}

/// Use to detect if running in a test environment, either `cargo test` or
/// `devimint`.
pub fn is_running_in_test_env() -> bool {
    let unit_test = cfg!(test);

    unit_test || is_env_var_set("NEXTEST") || is_env_var_set(FM_IN_DEVIMINT_ENV)
}

/// Get value of [`FEDIMINT_BUILD_CODE_VERSION_ENV`] at compile time
#[macro_export]
macro_rules! fedimint_build_code_version_env {
    () => {
        env!("FEDIMINT_BUILD_CODE_VERSION")
    };
}

/// Env var for bitcoin RPC kind (obsolete, use FM_DEFAULT_* instead)
pub const FM_BITCOIN_RPC_KIND_ENV: &str = "FM_BITCOIN_RPC_KIND";
/// Env var for bitcoin URL (obsolete, use FM_DEFAULT_* instead)
pub const FM_BITCOIN_RPC_URL_ENV: &str = "FM_BITCOIN_RPC_URL";

/// Env var for bitcoin RPC kind (default, used only as a default value for DKG
/// config settings)
pub const FM_DEFAULT_BITCOIN_RPC_KIND_ENV: &str = "FM_DEFAULT_BITCOIND_RPC_KIND";
/// Env var for bitcoin URL (default, used only as a default value for DKG
/// config settings)
pub const FM_DEFAULT_BITCOIN_RPC_URL_ENV: &str = "FM_DEFAULT_BITCOIND_RPC_URL";

/// Env var for bitcoin RPC kind (forced, takes priority over config settings)
pub const FM_FORCE_BITCOIN_RPC_KIND_ENV: &str = "FM_FORCE_BITCOIND_RPC_KIND";
/// Env var for bitcoin URL (default, takes priority over config settings)
pub const FM_FORCE_BITCOIN_RPC_URL_ENV: &str = "FM_FORCE_BITCOIND_RPC_URL";

/// Env var that can be set to point at the bitcoind's cookie file to use for
/// auth
pub const FM_BITCOIND_COOKIE_FILE_ENV: &str = "FM_BITCOIND_COOKIE_FILE";

/// `devimint` will set when code is running inside `devimint`
pub const FM_IN_DEVIMINT_ENV: &str = "FM_IN_DEVIMINT";

/// Configuration for the bitcoin RPC
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct BitcoinRpcConfig {
    pub kind: String,
    pub url: SafeUrl,
}

impl BitcoinRpcConfig {
    pub fn get_defaults_from_env_vars() -> anyhow::Result<Self> {
        Ok(Self {
            kind: env::var(FM_DEFAULT_BITCOIN_RPC_KIND_ENV)
                .or_else(|_| env::var(FM_BITCOIN_RPC_KIND_ENV).map(|v| {
                    warn!(target: LOG_CORE, "{FM_BITCOIN_RPC_KIND_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_KIND_ENV} instead");
                    v
                })
                )
                .with_context(|| {
                    anyhow::anyhow!("failure looking up env var {FM_DEFAULT_BITCOIN_RPC_KIND_ENV}")
                })?,
            url: env::var(FM_DEFAULT_BITCOIN_RPC_URL_ENV)
                .or_else(|_| env::var(FM_BITCOIN_RPC_URL_ENV).map(|v| {
                    warn!(target: LOG_CORE, "{FM_BITCOIN_RPC_URL_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_URL_ENV} instead");
                    v
                })
                )
                .with_context(|| {
                    anyhow::anyhow!("failure looking up env var {FM_DEFAULT_BITCOIN_RPC_URL_ENV}")
                })?.parse().with_context(|| {
                    anyhow::anyhow!("failure parsing env var {FM_DEFAULT_BITCOIN_RPC_URL_ENV}")
                })?
            ,
        })
    }
}
