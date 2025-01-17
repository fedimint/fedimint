use std::fmt::Display;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::Network;
use clap::{Parser, Subcommand};
use fedimint_core::util::SafeUrl;
use serde::{Deserialize, Serialize};

use super::envs;
use super::rpc::V1_API_ENDPOINT;
use crate::envs::{
    FM_LDK_BITCOIND_RPC_URL, FM_LDK_ESPLORA_SERVER_URL, FM_LDK_NETWORK, FM_LND_MACAROON_ENV,
    FM_LND_RPC_ADDR_ENV, FM_LND_TLS_CERT_ENV, FM_PORT_LDK,
};

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize, Eq, PartialEq)]
pub enum LightningMode {
    #[clap(name = "lnd")]
    Lnd {
        /// LND RPC address
        #[arg(long = "lnd-rpc-host", env = FM_LND_RPC_ADDR_ENV)]
        lnd_rpc_addr: String,

        /// LND TLS cert file path
        #[arg(long = "lnd-tls-cert", env = FM_LND_TLS_CERT_ENV)]
        lnd_tls_cert: String,

        /// LND macaroon file path
        #[arg(long = "lnd-macaroon", env = FM_LND_MACAROON_ENV)]
        lnd_macaroon: String,
    },
    #[clap(name = "ldk")]
    Ldk {
        /// LDK esplora server URL
        #[arg(long = "ldk-esplora-server-url", env = FM_LDK_ESPLORA_SERVER_URL)]
        esplora_server_url: Option<String>,

        /// LDK bitcoind server URL
        #[arg(long = "ldk-bitcoind-rpc-url", env = FM_LDK_BITCOIND_RPC_URL)]
        bitcoind_rpc_url: Option<String>,

        /// LDK network (defaults to regtest if not provided)
        #[arg(long = "ldk-network", env = FM_LDK_NETWORK, default_value = "regtest")]
        network: Network,

        /// LDK lightning server port
        #[arg(long = "ldk-lightning-port", env = FM_PORT_LDK)]
        lightning_port: u16,
    },
}

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
    #[arg(long = "lightning-module-mode", env = envs::FM_GATEWAY_LIGHTNING_MODULE_MODE_ENV, default_value_t = LightningModuleMode::All)]
    lightning_module_mode: LightningModuleMode,
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

        let bcrypt_password_hash = bcrypt::HashParts::from_str(&self.bcrypt_password_hash)?;

        Ok(GatewayParameters {
            listen: self.listen,
            versioned_api,
            bcrypt_password_hash,
            network: self.network,
            num_route_hints: self.num_route_hints,
            lightning_module_mode: self.lightning_module_mode,
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
