use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin::Network;
use clap::Parser;
use fedimint_core::util::SafeUrl;
use fedimint_ln_common::config::GatewayFee;

use super::envs;
use super::lightning::LightningMode;
use super::rpc::V1_API_ENDPOINT;

/// Command line parameters for starting the gateway. `mode`, `data_dir`,
/// `listen`, and `api_addr` are all required.
#[derive(Parser)]
#[command(version)]
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

    /// Gateway webserver authentication password
    #[arg(long = "password", env = envs::FM_GATEWAY_PASSWORD_ENV)]
    password: Option<String>,

    /// Bitcoin network this gateway will be running on
    #[arg(long = "network", env = envs::FM_GATEWAY_NETWORK_ENV)]
    network: Option<Network>,

    /// Configured gateway routing fees
    /// Format: <base_msat>,<proportional_millionths>
    #[arg(long = "default-fees", env = envs::FM_DEFAULT_GATEWAY_FEES_ENV)]
    default_fees: Option<GatewayFee>,

    /// Number of route hints to return in invoices
    #[arg(
        long = "num-route-hints",
        env = envs::FM_NUMBER_OF_ROUTE_HINTS_ENV,
        default_value_t = super::DEFAULT_NUM_ROUTE_HINTS
    )]
    num_route_hints: u32,
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
        Ok(GatewayParameters {
            listen: self.listen,
            versioned_api,
            password: self.password.clone(),
            network: self.network,
            num_route_hints: self.num_route_hints,
            fees: self.default_fees.clone(),
        })
    }
}

/// `GatewayParameters` is a helper struct that can be derived from
/// `GatewayOpts` that holds the CLI or environment variables that are specified
/// by the user.
///
/// If `GatewayConfiguration is set in the database, that takes precedence and
/// the optional parameters will have no affect.
#[derive(Clone, Debug)]
pub struct GatewayParameters {
    pub listen: SocketAddr,
    pub versioned_api: SafeUrl,
    pub password: Option<String>,
    pub network: Option<Network>,
    pub num_route_hints: u32,
    pub fees: Option<GatewayFee>,
}
