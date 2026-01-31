use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::Network;
use clap::{ArgGroup, Parser};
use fedimint_core::envs::{FM_IROH_DNS_ENV, FM_IROH_RELAY_ENV};
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{LightningMode, V1_API_ENDPOINT};
use fedimint_lnv2_common::gateway_api::PaymentFee;

use super::envs;
use crate::envs::{
    FM_BITCOIND_PASSWORD_ENV, FM_BITCOIND_URL_ENV, FM_BITCOIND_USERNAME_ENV, FM_ESPLORA_URL_ENV,
    FM_GATEWAY_METRICS_LISTEN_ADDR_ENV, FM_GATEWAY_SKIP_SETUP_ENV,
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
    api_addr: Option<SafeUrl>,

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

    /// The default routing fees that are applied to new federations
    #[arg(long = "default-routing-fees", env = envs::FM_DEFAULT_ROUTING_FEES_ENV, default_value_t = PaymentFee::TRANSACTION_FEE_DEFAULT)]
    default_routing_fees: PaymentFee,

    /// The default transaction fees that are applied to new federations
    #[arg(long = "default-transaction-fees", env = envs::FM_DEFAULT_TRANSACTION_FEES_ENV, default_value_t = PaymentFee::TRANSACTION_FEE_DEFAULT)]
    default_transaction_fees: PaymentFee,

    /// Gateway iroh listen address
    #[arg(long = "iroh-listen", env = envs::FM_GATEWAY_IROH_LISTEN_ADDR_ENV)]
    iroh_listen: Option<SocketAddr>,

    /// Gateway metrics listen address. If not set, defaults to localhost on the
    /// UI port + 1.
    #[arg(long = "metrics-listen", env = FM_GATEWAY_METRICS_LISTEN_ADDR_ENV)]
    metrics_listen: Option<SocketAddr>,

    /// Optional URL of the Iroh DNS server
    #[arg(long, env = FM_IROH_DNS_ENV)]
    iroh_dns: Option<SafeUrl>,

    /// Optional URLs of the Iroh relays to use for registering
    #[arg(long, env = FM_IROH_RELAY_ENV)]
    iroh_relays: Vec<SafeUrl>,

    #[arg(long, env = FM_GATEWAY_SKIP_SETUP_ENV, default_value_t = false)]
    skip_setup: bool,
}

impl GatewayOpts {
    /// Converts the command line parameters into a helper struct the Gateway
    /// uses to store runtime parameters.
    pub fn to_gateway_parameters(&self) -> anyhow::Result<GatewayParameters> {
        let versioned_api = self.api_addr.clone().map(|api_addr| {
            api_addr
                .join(V1_API_ENDPOINT)
                .expect("Could not join v1 api_addr")
        });
        let bcrypt_password_hash = bcrypt::HashParts::from_str(&self.bcrypt_password_hash)?;

        // Default metrics listen to localhost on UI port + 1
        let metrics_listen = self.metrics_listen.unwrap_or_else(|| {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                self.listen.port() + 1,
            )
        });

        Ok(GatewayParameters {
            listen: self.listen,
            versioned_api,
            bcrypt_password_hash,
            network: self.network,
            num_route_hints: self.num_route_hints,
            default_routing_fees: self.default_routing_fees,
            default_transaction_fees: self.default_transaction_fees,
            iroh_listen: self.iroh_listen,
            iroh_dns: self.iroh_dns.clone(),
            iroh_relays: self.iroh_relays.clone(),
            skip_setup: self.skip_setup,
            metrics_listen,
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
    pub versioned_api: Option<SafeUrl>,
    pub bcrypt_password_hash: bcrypt::HashParts,
    pub network: Network,
    pub num_route_hints: u32,
    pub default_routing_fees: PaymentFee,
    pub default_transaction_fees: PaymentFee,
    pub iroh_listen: Option<SocketAddr>,
    pub iroh_dns: Option<SafeUrl>,
    pub iroh_relays: Vec<SafeUrl>,
    pub skip_setup: bool,
    pub metrics_listen: SocketAddr,
}
