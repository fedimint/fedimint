use std::ffi::OsStr;

use url::Url;

/// Name of the env value used for passing bitcoind rpc url to modules that need
/// it
pub const FM_BITCOIND_RPC_ENV: &str = "FM_BITCOIND_RPC";

/// Name of the env value used for passing electrum rpc url to modules that need
/// it
pub const FM_ELECTRUM_RPC_ENV: &str = "FM_ELECTRUM_RPC";

/// Name of the env value used for passing esplora rpc url to modules that need
/// it
pub const FM_ESPLORA_RPC_ENV: &str = "FM_ESPLORA_RPC";

/// Default url that will be used if [`FM_BITCOIND_RPC_ENV`] is not set
pub const FM_BITCOIND_RPC_DEFAULT_FALLBACK: &str = "http://127.0.0.1:8332";

/// Bitcoin RPC backend
pub enum BitcoindRpcBackend {
    /// Bitcoin Core RPC
    Bitcoind(Url),
    /// Electrum RPC
    Electrum(Url),
    /// Esplora RPC
    Esplora(Url),
}

pub enum BitcoinRpcBackendType {
    Bitcoind,
    Electrum,
    Esplora,
}

/// Get the value of url the module would use by reading it from process
/// environment
///
/// Should be used in test code only to mimic prod code behavior
pub fn read_bitcoin_backend_from_global_env() -> anyhow::Result<BitcoindRpcBackend> {
    select_bitcoin_backend_from_envs(
        std::env::var_os(FM_BITCOIND_RPC_ENV).as_deref(),
        std::env::var_os(FM_ELECTRUM_RPC_ENV).as_deref(),
        std::env::var_os(FM_ESPLORA_RPC_ENV).as_deref(),
    )
}

/// Get the `BitcoinRpcBackend` variant to use by the given parameters
///
/// It uses in the first one available, in order (left-to-right), bitcoind,
/// electrum and esplora, or fallback bitcoind.
pub fn select_bitcoin_backend_from_envs(
    bitcoind_rpc: Option<&OsStr>,
    electrum_rpc: Option<&OsStr>,
    esplora_rpc: Option<&OsStr>,
) -> anyhow::Result<BitcoindRpcBackend> {
    Ok(if let Some(val) = bitcoind_rpc {
        BitcoindRpcBackend::Bitcoind(fm_backend_rpc_env_value_to_url(val)?)
    } else if let Some(val) = electrum_rpc {
        BitcoindRpcBackend::Electrum(fm_backend_rpc_env_value_to_url(val)?)
    } else if let Some(val) = esplora_rpc {
        BitcoindRpcBackend::Esplora(fm_backend_rpc_env_value_to_url(val)?)
    } else {
        BitcoindRpcBackend::Bitcoind(Url::parse(FM_BITCOIND_RPC_DEFAULT_FALLBACK)?)
    })
}

/// Get the value of bitcoin rpc url to use, from the value of env variable
///
/// Useful in places where variable value is already available.
fn fm_backend_rpc_env_value_to_url(value: &OsStr) -> anyhow::Result<Url> {
    Ok(Url::parse(value.to_str().ok_or_else(|| {
        anyhow::format_err!("Url not ascii text")
    })?)?)
}
