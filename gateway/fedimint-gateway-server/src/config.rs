use std::fmt::Display;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::Network;
use clap::{ArgGroup, Parser};
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{LightningMode, V1_API_ENDPOINT};
use std::collections::HashMap;
use super::envs;
use crate::envs::{
    FM_BITCOIND_PASSWORD_ENV, FM_BITCOIND_URL_ENV, FM_BITCOIND_USERNAME_ENV, FM_ESPLORA_URL_ENV,
};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DatabaseBackend {
    /// Use RocksDB database backend
    #[value(name = "rocksdb")]
    RocksDb,
    /// Use CursedRedb database backend (hybrid memory/redb)
    #[value(name = "cursed-redb")]
    CursedRedb,
}

/// Command line parameters for starting the gateway. `mode`, `data_dir`,
/// `listen`, and `api_addr` are all required.
#[derive(Parser)]
#[command(version)]
#[command(
    group(
        ArgGroup::new("bitcoind_password_auth")
           .args(["bitcoind_password"])
           .multiple(false)
    ),
    group(
        ArgGroup::new("bitcoind_auth")
            .args(["bitcoind_url"])
            .requires("bitcoind_password_auth")
            .requires_all(["bitcoind_username", "bitcoind_url"])
    ),
    group(
        ArgGroup::new("bitcoin_rpc")
            .required(true)
            .multiple(true)
            .args(["bitcoind_url", "esplora_url"])
    )
)]
pub struct GatewayOpts {
    #[clap(subcommand)]
    pub mode: LightningMode,

    /// Path to folder containing gateway config and data files
    #[arg(long = "data-dir", env = envs::FM_GATEWAY_DATA_DIR_ENV)]
    pub data_dir: PathBuf,

    /// Gateway webserver listen address
    #[arg(long = "listen", env = envs::FM_GATEWAY_LISTEN_ADDR_ENV)]
    listen: SocketAddr,

    /// Public URL from which the webserver API is reachable
    #[arg(long = "api-addr", env = envs::FM_GATEWAY_API_ADDR_ENV)]
    api_addr: SafeUrl,

    /// Gateway webserver authentication bcrypt password hash
    #[arg(long = "bcrypt-password-hash", env = envs::FM_GATEWAY_BCRYPT_PASSWORD_HASH_ENV)]
    bcrypt_password_hash: String,

    /// Bitcoin network this gateway will be running on
    #[arg(long = "network", env = envs::FM_GATEWAY_NETWORK_ENV)]
    network: Network,

    /// Number of route hints to return in invoices
    #[arg(
        long = "num-route-hints",
        env = envs::FM_NUMBER_OF_ROUTE_HINTS_ENV,
        default_value_t = super::DEFAULT_NUM_ROUTE_HINTS
    )]
    num_route_hints: u32,

    /// The Lightning module to use: LNv1, LNv2, or both
    #[arg(long = "lightning-module-mode", env = envs::FM_GATEWAY_LIGHTNING_MODULE_MODE_ENV, default_value_t = LightningModuleMode::LNv1)]
    lightning_module_mode: LightningModuleMode,

    /// Database backend to use.
    #[arg(long, env = envs::FM_DB_BACKEND_ENV, value_enum, default_value = "rocksdb")]
    pub db_backend: DatabaseBackend,

    /// The username to use when connecting to bitcoind
    #[arg(long, env = FM_BITCOIND_USERNAME_ENV)]
    pub bitcoind_username: Option<String>,

    /// The password to use when connecting to bitcoind
    #[arg(long, env = FM_BITCOIND_PASSWORD_ENV)]
    pub bitcoind_password: Option<String>,

    /// Bitcoind RPC URL, e.g. <http://127.0.0.1:8332>
    /// This should not include authentication parameters, they should be
    /// included in `FM_BITCOIND_USERNAME` and `FM_BITCOIND_PASSWORD`
    #[arg(long, env = FM_BITCOIND_URL_ENV)]
    pub bitcoind_url: Option<SafeUrl>,

    /// Esplora HTTP base URL, e.g. <https://mempool.space/api>
    #[arg(long, env = FM_ESPLORA_URL_ENV)]
    pub esplora_url: Option<SafeUrl>,

    #[arg(long = "vss-url", env = "FM_VSS_URL")]
    vss_url: Option<SafeUrl>,

    #[arg(long = "vss-auth-headers", env = "FM_VSS_AUTH_HEADERS")]
    vss_auth_headers: Option<String>,

    #[arg(long = "vss-fallback-enabled", env = "FM_VSS_FALLBACK_ENABLED", default_value_t = true)]
    pub vss_fallback_enabled: bool,
}

impl GatewayOpts {
    /// Converts the command line parameters into a helper struct the Gateway
    /// uses to store runtime parameters.
    pub fn to_gateway_parameters(&self) -> anyhow::Result<GatewayParameters> {
        let versioned_api = self.api_addr.join(V1_API_ENDPOINT).map_err(|e| {
            anyhow::anyhow!(
                "Failed to version gateway API address: {api_addr:?}, error: {e:?}",
                api_addr = self.api_addr,
            )
        })?;
        let vss_auth_headers = if let Some(headers_json) = &self.vss_auth_headers {
            serde_json::from_str(headers_json)?
        } else {
            HashMap::new()
        };

        let bcrypt_password_hash = bcrypt::HashParts::from_str(&self.bcrypt_password_hash)?;

        Ok(GatewayParameters {
            listen: self.listen,
            versioned_api,
            bcrypt_password_hash,
            network: self.network,
            num_route_hints: self.num_route_hints,
            lightning_module_mode: self.lightning_module_mode,
            vss_url: self.vss_url.clone(),
            vss_auth_headers,
            vss_fallback_enabled: self.vss_fallback_enabled,
        })
    }
}

/// `GatewayParameters` is a helper struct that can be derived from
/// `GatewayOpts` that holds the CLI or environment variables that are specified
/// by the user.
///
/// If `GatewayConfiguration is set in the database, that takes precedence and
/// the optional parameters will have no affect.
#[derive(Debug)]
pub struct GatewayParameters {
    pub listen: SocketAddr,
    pub versioned_api: SafeUrl,
    pub bcrypt_password_hash: bcrypt::HashParts,
    pub network: Network,
    pub num_route_hints: u32,
    pub lightning_module_mode: LightningModuleMode,
    pub vss_url: Option<SafeUrl>,
    pub vss_auth_headers: HashMap<String, String>,
    pub vss_fallback_enabled: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LightningModuleMode {
    LNv1,
    LNv2,
    All,
}

impl Display for LightningModuleMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningModuleMode::LNv1 => write!(f, "LNv1"),
            LightningModuleMode::LNv2 => write!(f, "LNv2"),
            LightningModuleMode::All => write!(f, "All"),
        }
    }
}

impl FromStr for LightningModuleMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mode = match s {
            "LNv1" => LightningModuleMode::LNv1,
            "LNv2" => LightningModuleMode::LNv2,
            _ => LightningModuleMode::All,
        };

        Ok(mode)
    }
}
