use std::collections::BTreeMap;
use std::str::FromStr;
use std::{cmp, env};

use anyhow::Context;
use fedimint_core::util::SafeUrl;
use fedimint_derive::{Decodable, Encodable};
use fedimint_logging::LOG_CORE;
use jsonrpsee_core::Serialize;
use serde::Deserialize;
use tracing::warn;

use crate::util::FmtCompact as _;

/// In tests we want to routinely enable an extra unknown module to ensure
/// all client code handles correct modules that client doesn't know about.
pub const FM_USE_UNKNOWN_MODULE_ENV: &str = "FM_USE_UNKNOWN_MODULE";

pub const FM_ENABLE_MODULE_LNV1_ENV: &str = "FM_ENABLE_MODULE_LNV1";
pub const FM_ENABLE_MODULE_LNV2_ENV: &str = "FM_ENABLE_MODULE_LNV2";
pub const FM_ENABLE_MODULE_WALLETV2_ENV: &str = "FM_ENABLE_MODULE_WALLETV2";

/// Disable mint base fees for testing and development environments
pub const FM_DISABLE_BASE_FEES_ENV: &str = "FM_DISABLE_BASE_FEES";

/// Print sensitive secrets without redacting them. Use only for debugging.
pub const FM_DEBUG_SHOW_SECRETS_ENV: &str = "FM_DEBUG_SHOW_SECRETS";

/// Check if env variable is set and not equal `0` or `false` which are common
/// ways to disable something.
pub fn is_env_var_set(var: &str) -> bool {
    let Some(val) = std::env::var_os(var) else {
        return false;
    };
    match val.as_encoded_bytes() {
        b"0" | b"false" => false,
        b"1" | b"true" => true,
        _ => {
            warn!(
                target: LOG_CORE,
                %var,
                val = %val.to_string_lossy(),
                "Env var value invalid is invalid and ignored, assuming `true`"
            );
            true
        }
    }
}

/// Check if env variable is set and not equal `0` or `false` which are common
/// ways to disable a setting. `None` if env var not set at all, which allows
/// handling the default value.
pub fn is_env_var_set_opt(var: &str) -> Option<bool> {
    let val = std::env::var_os(var)?;
    match val.as_encoded_bytes() {
        b"0" | b"false" => Some(false),
        b"1" | b"true" => Some(true),
        _ => {
            warn!(
                target: LOG_CORE,
                %var,
                val = %val.to_string_lossy(),
                "Env var value invalid is invalid and ignored"
            );
            None
        }
    }
}

/// Use to detect if running in a test environment, either `cargo test` or
/// `devimint`.
pub fn is_running_in_test_env() -> bool {
    let unit_test = cfg!(test);

    unit_test || is_env_var_set("NEXTEST") || is_env_var_set(FM_IN_DEVIMINT_ENV)
}

/// Use to allow `process_output` to process RBF withdrawal outputs.
pub fn is_rbf_withdrawal_enabled() -> bool {
    is_env_var_set("FM_UNSAFE_ENABLE_RBF_WITHDRAWAL")
}

/// Get value of `FEDIMINT_BUILD_CODE_VERSION` at compile time
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
/// Env var how often to poll bitcoin source
pub const FM_BITCOIN_POLLING_INTERVAL_SECS_ENV: &str = "FM_BITCOIN_POLLING_INTERVAL_SECS";

/// Env var for bitcoin RPC kind (default, used only as a default value for DKG
/// config settings)
pub const FM_DEFAULT_BITCOIN_RPC_KIND_ENV: &str = "FM_DEFAULT_BITCOIN_RPC_KIND";
pub const FM_DEFAULT_BITCOIN_RPC_KIND_BAD_ENV: &str = "FM_DEFAULT_BITCOIND_RPC_KIND";
/// Env var for bitcoin URL (default, used only as a default value for DKG
/// config settings)
pub const FM_DEFAULT_BITCOIN_RPC_URL_ENV: &str = "FM_DEFAULT_BITCOIN_RPC_URL";
pub const FM_DEFAULT_BITCOIN_RPC_URL_BAD_ENV: &str = "FM_DEFAULT_BITCOIND_RPC_URL";

/// Env var for bitcoin RPC kind (forced, takes priority over config settings)
pub const FM_FORCE_BITCOIN_RPC_KIND_ENV: &str = "FM_FORCE_BITCOIN_RPC_KIND";
pub const FM_FORCE_BITCOIN_RPC_KIND_BAD_ENV: &str = "FM_FORCE_BITCOIND_RPC_BAD_KIND";
/// Env var for bitcoin URL (default, takes priority over config settings)
pub const FM_FORCE_BITCOIN_RPC_URL_ENV: &str = "FM_FORCE_BITCOIN_RPC_URL";
pub const FM_FORCE_BITCOIN_RPC_URL_BAD_ENV: &str = "FM_FORCE_BITCOIND_RPC_URL";

/// Env var to override iroh connectivity
///
/// Comma separated key-value list (`<node_id>=<ticket>,<node_id>=<ticket>,...`)
pub const FM_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_IROH_CONNECT_OVERRIDES";

/// Env var to override iroh connectivity
///
/// Comma separated key-value list (`<node_id>=<ticket>,<node_id>=<ticket>,...`)
pub const FM_GW_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_GW_IROH_CONNECT_OVERRIDES";

/// Env var to override iroh DNS server
pub const FM_IROH_DNS_ENV: &str = "FM_IROH_DNS";

/// Env var to override iroh relays server
pub const FM_IROH_RELAY_ENV: &str = "FM_IROH_RELAY";

/// Env var to disable Iroh's use of DHT
pub const FM_IROH_DHT_ENABLE_ENV: &str = "FM_IROH_DHT_ENABLE";

/// Env var to disable default n0 discovery
pub const FM_IROH_N0_DISCOVERY_ENABLE_ENV: &str = "FM_IROH_N0_DISCOVERY_ENABLE";

/// Env var to disable default pkarr resolver
pub const FM_IROH_PKARR_RESOLVER_ENABLE_ENV: &str = "FM_IROH_PKARR_RESOLVER_ENABLE";

/// Env var to disable default pkarr publisher
pub const FM_IROH_PKARR_PUBLISHER_ENABLE_ENV: &str = "FM_IROH_PKARR_PUBLISHER_ENABLE";

/// Env var to disable Iroh's use of relays
pub const FM_IROH_RELAYS_ENABLE_ENV: &str = "FM_IROH_RELAYS_ENABLE";

/// Env var to override tcp api connectivity
///
/// Comma separated key-value list (`peer_id=url,peer_id=url`)
pub const FM_WS_API_CONNECT_OVERRIDES_ENV: &str = "FM_WS_API_CONNECT_OVERRIDES";

pub const FM_IROH_API_SECRET_KEY_OVERRIDE_ENV: &str = "FM_IROH_API_SECRET_KEY_OVERRIDE";
pub const FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV: &str = "FM_IROH_P2P_SECRET_KEY_OVERRIDE";

/// List of json api endpoint sources to use as a source of
/// fee rate estimation.
///
/// `;`-separated list of urls with part after `#`
/// ("fragment") specifying jq filter to extract sats/vB fee rate.
/// Eg. `https://mempool.space/api/v1/fees/recommended#.halfHourFee`
///
/// Note that `#` is a standalone separator and *not* parsed as a part of the
/// Url. Which means there's no need to escape it.
pub const FM_WALLET_FEERATE_SOURCES_ENV: &str = "FM_WALLET_FEERATE_SOURCES";

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
        kind: env::var(FM_FORCE_BITCOIN_RPC_KIND_ENV)
            .or_else(|_| env::var(FM_DEFAULT_BITCOIN_RPC_KIND_ENV))
            .or_else(|_| env::var(FM_BITCOIN_RPC_KIND_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_BITCOIN_RPC_KIND_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_KIND_ENV} instead");
            }))
            .or_else(|_| env::var(FM_FORCE_BITCOIN_RPC_KIND_BAD_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_FORCE_BITCOIN_RPC_KIND_BAD_ENV} is obsolete, use {FM_FORCE_BITCOIN_RPC_KIND_ENV} instead");
            }))
            .or_else(|_| env::var(FM_DEFAULT_BITCOIN_RPC_KIND_BAD_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_DEFAULT_BITCOIN_RPC_KIND_BAD_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_KIND_ENV} instead");
            }))
            .with_context(|| {
                anyhow::anyhow!("failure looking up env var for Bitcoin RPC kind")
            })?,
        url: env::var(FM_FORCE_BITCOIN_RPC_URL_ENV)
            .or_else(|_| env::var(FM_DEFAULT_BITCOIN_RPC_URL_ENV))
            .or_else(|_| env::var(FM_BITCOIN_RPC_URL_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_BITCOIN_RPC_URL_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_URL_ENV} instead");
            }))
            .or_else(|_| env::var(FM_FORCE_BITCOIN_RPC_URL_BAD_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_FORCE_BITCOIN_RPC_URL_BAD_ENV} is obsolete, use {FM_FORCE_BITCOIN_RPC_URL_ENV} instead");
            }))
            .or_else(|_| env::var(FM_DEFAULT_BITCOIN_RPC_URL_BAD_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_DEFAULT_BITCOIN_RPC_URL_BAD_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_URL_ENV} instead");
            }))
            .with_context(|| {
                anyhow::anyhow!("failure looking up env var for Bitcoin RPC URL")
            })?
            .parse()
            .with_context(|| {
                anyhow::anyhow!("failure parsing Bitcoin RPC URL")
            })?,
    })
    }
}

pub fn parse_kv_list_from_env<K, V>(env: &str) -> anyhow::Result<BTreeMap<K, V>>
where
    K: FromStr + cmp::Ord,
    <K as FromStr>::Err: std::error::Error,
    V: FromStr,
    <V as FromStr>::Err: std::error::Error,
{
    let mut map = BTreeMap::new();
    let Ok(env_value) = std::env::var(env) else {
        return Ok(BTreeMap::new());
    };
    for kv in env_value.split(',') {
        let kv = kv.trim();

        if kv.is_empty() {
            continue;
        }

        if let Some((k, v)) = kv.split_once('=') {
            let Some(k) = K::from_str(k)
                .inspect_err(|err| {
                    warn!(
                        target: LOG_CORE,
                        err = %err.fmt_compact(),
                        "Error parsing value"
                    );
                })
                .ok()
            else {
                continue;
            };
            let Some(v) = V::from_str(v)
                .inspect_err(|err| {
                    warn!(
                        target: LOG_CORE,
                        err = %err.fmt_compact(),
                        "Error parsing value"
                    );
                })
                .ok()
            else {
                continue;
            };

            map.insert(k, v);
        }
    }

    Ok(map)
}
