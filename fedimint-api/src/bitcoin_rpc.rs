use std::ffi::OsStr;

use url::Url;

/// Name of the env value used for passing bitcoind rpc url to modules that need it
pub const FM_BITCOIND_RPC_ENV: &str = "FM_BITCOIND_RPC";

/// Name of the env value used for passing electrum rpc url to modules that need it
pub const FM_ELECTRUM_RPC_ENV: &str = "FM_ELECTRUM_RPC";

/// Default url that will be used if [`FM_BITCOIND_RPC_ENV`] is not set
pub const FM_BITCOIND_RPC_DEFAULT_FALLBACK: &str = "http://127.0.0.1:8332";

/// Bitcoin RPC backend
pub enum BitcoindRpcBackend {
    /// Bitcoin Core RPC
    Bitcoind(Url),
    /// Electrum RPC
    Electrum(Url),
}

pub enum BitcoinRpcBackendType {
    Bitcoind,
    Electrum,
}

/// Get the value of url the module would use by reading it from process environemnt
///
/// Should be used in test code only to mimick prod code behavior
pub fn read_bitcoin_backend_from_global_env() -> anyhow::Result<BitcoindRpcBackend> {
    select_bitcoin_backend_from_envs(
        std::env::var_os(FM_BITCOIND_RPC_ENV).as_deref(),
        std::env::var_os(FM_ELECTRUM_RPC_ENV).as_deref(),
    )
}

pub fn select_bitcoin_backend_from_envs(
    bitcoind_rpc: Option<&OsStr>,
    electrum_rpc: Option<&OsStr>,
) -> anyhow::Result<BitcoindRpcBackend> {
    Ok(if let Some(val) = bitcoind_rpc {
        BitcoindRpcBackend::Bitcoind(fm_bitcoind_rpc_env_value_to_url(Some(val))?)
    } else if let Some(val) = electrum_rpc {
        BitcoindRpcBackend::Electrum(fm_electrum_rpc_env_value_to_url(val)?)
    } else {
        BitcoindRpcBackend::Bitcoind(fm_bitcoind_rpc_env_value_to_url(None)?)
    })
}

/// Get the value of bitcoin rpc url to use, from the value of env variable
///
/// Useful in places where variable value is already available.
fn fm_bitcoind_rpc_env_value_to_url(value: Option<&OsStr>) -> anyhow::Result<Url> {
    Ok(if let Some(url_str) = value {
        Url::parse(
            url_str
                .to_str()
                .ok_or_else(|| anyhow::format_err!("Url not ascii text"))?,
        )?
    } else {
        Url::parse(FM_BITCOIND_RPC_DEFAULT_FALLBACK)?
    })
}

pub fn fm_electrum_rpc_env_value_to_url(value: &OsStr) -> anyhow::Result<Url> {
    Ok(Url::parse(value.to_str().ok_or_else(|| {
        anyhow::format_err!("Url not ascii text")
    })?)?)
}
