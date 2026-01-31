#![allow(non_snake_case)]

mod net_overrides;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
pub trait ToEnvVar {
    fn to_env_value(&self) -> Option<String> {
        panic!("Must implement one of the two ToEnvVar methods");
    }

    fn to_env_values(&self, base: &str) -> impl Iterator<Item = (String, String)> {
        self.to_env_value()
            .into_iter()
            .map(|v| (base.to_owned(), v))
    }
}

macro_rules! declare_vars {
    ($struct:ident = ($($args:tt)*) =>
        {
            $($name:ident : $ty:ty = $value:expr_2021; env: $env:expr_2021;)*
        }
    ) => {
        #[derive(Clone, Debug)]
        pub struct $struct {
            $(
                #[allow(unused)]
                pub $name: $ty
            ),*
        }

        impl $struct {
            pub async fn init($($args)*) -> ::anyhow::Result<Self> {
                $(let $name: $ty = $value.into();)*
                Ok(Self {
                    $($name),*
                })
            }

            pub fn vars(&self) -> impl Iterator<Item = (String, String)> + use<> {
                let mut env = ::std::vec::Vec::new();
                $(
                    for (env_name, value) in $crate::vars::ToEnvVar::to_env_values(&self.$name, $env) {
                        env.push((env_name, value));
                    }
                )*
                env.into_iter()
            }
        }
    };
}

impl ToEnvVar for PathBuf {
    fn to_env_value(&self) -> Option<String> {
        Some(self.as_os_str().to_str().expect("must be utf8").to_owned())
    }
}

impl ToEnvVar for String {
    fn to_env_value(&self) -> Option<String> {
        Some(self.to_owned())
    }
}

impl ToEnvVar for usize {
    fn to_env_value(&self) -> Option<String> {
        Some(self.to_string())
    }
}

impl ToEnvVar for u16 {
    fn to_env_value(&self) -> Option<String> {
        Some(self.to_string())
    }
}

impl<T: ToEnvVar> ToEnvVar for Option<T> {
    fn to_env_value(&self) -> Option<String> {
        self.as_ref().and_then(ToEnvVar::to_env_value)
    }
}

impl ToEnvVar for ApiSecrets {
    fn to_env_value(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        Some(self.get_all().join(","))
    }
}

pub async fn mkdir(dir: PathBuf) -> anyhow::Result<PathBuf> {
    if !dir.exists() {
        tokio::fs::create_dir(&dir).await?;
    }
    Ok(dir)
}

use fedimint_core::envs::{
    FM_DEFAULT_BITCOIN_RPC_KIND_ENV, FM_DEFAULT_BITCOIN_RPC_URL_ENV, FM_FORCE_BITCOIN_RPC_KIND_ENV,
    FM_FORCE_BITCOIN_RPC_URL_ENV, FM_IN_DEVIMINT_ENV, FM_IROH_API_SECRET_KEY_OVERRIDE_ENV,
    FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV, FM_USE_UNKNOWN_MODULE_ENV,
};
use fedimint_core::{NumPeers, PeerId};
use fedimint_portalloc::port_alloc;
use fedimint_server::net::api::ApiSecrets;
use fedimintd_envs::FM_FORCE_API_SECRETS_ENV;
use format as f;
use net_overrides::{FederationsNetOverrides, FedimintdPeerOverrides};

use crate::federation::{
    FEDIMINTD_METRICS_PORT_OFFSET, FEDIMINTD_UI_PORT_OFFSET, PORTS_PER_FEDIMINTD,
};
use crate::vars::net_overrides::GatewaydNetOverrides;

pub fn utf8(path: &Path) -> &str {
    path.as_os_str().to_str().expect("must be valid utf8")
}

declare_vars! {
    Global = (test_dir: &Path, num_feds: usize, fed_size: usize, offline_nodes: usize, federation_base_ports: u16, num_gateways: usize, gw_base_port: u16) =>
    {
        FM_USE_UNKNOWN_MODULE: String = std::env::var(FM_USE_UNKNOWN_MODULE_ENV).unwrap_or_else(|_| "1".into()); env: "FM_USE_UNKNOWN_MODULE";

        FM_FORCE_API_SECRETS: ApiSecrets = std::env::var(FM_FORCE_API_SECRETS_ENV).ok().and_then(|s| {
            ApiSecrets::from_str(&s).ok()
        }).unwrap_or_default(); env: FM_FORCE_API_SECRETS_ENV;

        FM_API_SECRET: Option<String> = std::env::var("FM_API_SECRET").ok().or_else(|| FM_FORCE_API_SECRETS.get_active()); env: "FM_API_SECRET";

        FM_IN_DEVIMINT: String = "1".to_string(); env: FM_IN_DEVIMINT_ENV;
        FM_SKIP_REL_NOTES_ACK: String = "1".to_string(); env: "FM_SKIP_REL_NOTES_ACK";

        FM_FED_SIZE: usize = fed_size; env: "FM_FED_SIZE";
        FM_NUM_FEDS: usize = num_feds; env: "FM_NUM_FEDS";
        FM_OFFLINE_NODES: usize = offline_nodes; env: "FM_OFFLINE_NODES";
        FM_TMP_DIR: PathBuf = mkdir(test_dir.into()).await?; env: "FM_TMP_DIR";
        FM_TEST_DIR: PathBuf = FM_TMP_DIR.clone(); env: "FM_TEST_DIR";
        FM_TEST_FAST_WEAK_CRYPTO: String = "1"; env: "FM_TEST_FAST_WEAK_CRYPTO";
        FM_LOGS_DIR: PathBuf = mkdir(FM_TEST_DIR.join("logs")).await?; env: "FM_LOGS_DIR";

        FM_PORT_BTC_RPC: u16 = port_alloc(1)?; env: "FM_PORT_BTC_RPC";
        FM_PORT_BTC_P2P: u16 = port_alloc(1)?; env: "FM_PORT_BTC_P2P";
        FM_PORT_BTC_ZMQ_PUB_RAW_BLOCK: u16 = port_alloc(1)?; env: "FM_PORT_BTC_ZMQ_PUB_RAW_BLOCK";
        FM_PORT_BTC_ZMQ_PUB_RAW_TX: u16 = port_alloc(1)?; env: "FM_PORT_BTC_ZMQ_PUB_RAW_TX";
        FM_PORT_LND_LISTEN: u16 = port_alloc(1)?; env: "FM_PORT_LND_LISTEN";
        FM_PORT_LDK: u16 = port_alloc(1)?; env: "FM_PORT_LDK";
        FM_PORT_LDK2: u16 = port_alloc(1)?; env: "FM_PORT_LDK";
        FM_PORT_LND_RPC: u16 = port_alloc(1)?; env: "FM_PORT_LND_RPC";
        FM_PORT_LND_REST: u16 = port_alloc(1)?; env: "FM_PORT_LND_REST";
        FM_PORT_ESPLORA: u16 = port_alloc(1)?; env: "FM_PORT_ESPLORA";
        FM_PORT_ESPLORA_MONITORING: u16 = port_alloc(1)?; env: "FM_PORT_ESPLORA_MONITORING";
        FM_PORT_GW_LND: u16 = port_alloc(1)?; env: "FM_PORT_GW_LND";
        FM_PORT_GW_LND_METRICS: u16 = port_alloc(1)?; env: "FM_PORT_GW_LND_METRICS";
        FM_PORT_GW_LDK: u16 = port_alloc(1)?; env: "FM_PORT_GW_LDK";
        FM_PORT_GW_LDK_METRICS: u16 = port_alloc(1)?; env: "FM_PORT_GW_LDK_METRICS";
        FM_PORT_GW_LDK2: u16 = port_alloc(1)?; env: "FM_PORT_GW_LDK2";
        FM_PORT_GW_LDK2_METRICS: u16 = port_alloc(1)?; env: "FM_PORT_GW_LDK2_METRICS";
        FM_PORT_FAUCET: u16 = 15243u16; env: "FM_PORT_FAUCET";
        FM_PORT_RECURRINGD: u16 = port_alloc(1)?; env: "FM_PORT_RECURRINGD";
        FM_PORT_RECURRINGDV2: u16 = port_alloc(1)?; env: "FM_PORT_RECURRINGDV2";

        FM_FEDERATION_BASE_PORT: u16 = federation_base_ports; env: "FM_FEDERATION_BASE_PORT";
        fedimintd_overrides: FederationsNetOverrides = FederationsNetOverrides::new(FM_FEDERATION_BASE_PORT, num_feds, NumPeers::from(fed_size)); env: "NOT_USED_FOR_ANYTHING";
        gatewayd_overrides: GatewaydNetOverrides = GatewaydNetOverrides::new(gw_base_port, num_gateways); env: "NOT_USED_FOR_ANYTHING";

        FM_LND_DIR: PathBuf = mkdir(FM_TEST_DIR.join("lnd")).await?; env: "FM_LND_DIR";
        FM_LDK_DIR: PathBuf = mkdir(FM_TEST_DIR.join("ldk")).await?; env: "FM_LDK_DIR";
        FM_BTC_DIR: PathBuf = mkdir(FM_TEST_DIR.join("bitcoin")).await?; env: "FM_BTC_DIR";
        FM_DATA_DIR: PathBuf = FM_TEST_DIR.clone(); env: "FM_DATA_DIR";
        FM_CLIENT_BASE_DIR: PathBuf = mkdir(FM_TEST_DIR.join("clients")).await?; env: "FM_CLIENT_BASE_DIR";
        FM_CLIENT_DIR: PathBuf = mkdir(FM_TEST_DIR.join("clients").join("default-0")).await?; env: "FM_CLIENT_DIR";
        FM_ESPLORA_DIR: PathBuf = mkdir(FM_TEST_DIR.join("esplora")).await?; env: "FM_ESPLORA_DIR";
        FM_READY_FILE: PathBuf = FM_TEST_DIR.join("ready"); env: "FM_READY_FILE";

        FM_LND_RPC_ADDR: String = f!("https://localhost:{FM_PORT_LND_RPC}"); env: "FM_LND_RPC_ADDR";
        FM_LND_TLS_CERT: PathBuf = FM_LND_DIR.join("tls.cert"); env: "FM_LND_TLS_CERT";
        FM_LND_MACAROON: PathBuf = FM_LND_DIR.join("data/chain/bitcoin/regtest/admin.macaroon"); env: "FM_LND_MACAROON";

        // TODO(support:v0.5): Remove this. It was used prior to `FM_GATEWAY_BCRYPT_PASSWORD_HASH` to provide a plaintext password to the gateway.
        FM_GATEWAY_PASSWORD: String = "theresnosecondbest"; env: "FM_GATEWAY_PASSWORD";
        FM_GATEWAY_SKIP_SETUP: String = "true"; env: "FM_GATEWAY_SKIP_SETUP";

        // Bcrypt hash of "theresnosecondbest" with a cost of 10.
        FM_GATEWAY_BCRYPT_PASSWORD_HASH: String = "$2y$10$Q/UTDeO84VGG1mRncxw.Nubqyi/HsNRJ40k0TSexFy9eVess1yi/u"; env: "FM_GATEWAY_BCRYPT_PASSWORD_HASH";

        FM_GATEWAY_SKIP_WAIT_FOR_SYNC: String = "1"; env: "FM_GATEWAY_SKIP_WAIT_FOR_SYNC";
        FM_GATEWAY_NETWORK: String = "regtest"; env: "FM_GATEWAY_NETWORK";
        FM_DEFAULT_ROUTING_FEES: String = "0,0"; env: "FM_DEFAULT_ROUTING_FEES";

        FM_FAUCET_BIND_ADDR: String = f!("0.0.0.0:{FM_PORT_FAUCET}"); env: "FM_FAUCET_BIND_ADDR";

        // clients env: "// ";
        FM_LNCLI: String = f!("{lncli} -n regtest --lnddir={lnddir} --rpcserver=localhost:{FM_PORT_LND_RPC}",
            lncli = crate::util::get_lncli_path().join(" "),
            lnddir = utf8(&FM_LND_DIR)); env: "FM_LNCLI";
        FM_BTC_CLIENT: String = f!("{bitcoin_cli} -regtest -rpcuser=bitcoin -rpcpassword=bitcoin -datadir={datadir}",             bitcoin_cli = crate::util::get_bitcoin_cli_path().join(" "),
            datadir = utf8(&FM_BTC_DIR)); env: "FM_BTC_CLIENT";

        FM_MINT_CLIENT: String = f!("{fedimint_cli} --data-dir {datadir}",
            fedimint_cli = crate::util::get_fedimint_cli_path().join(" "),
            datadir = utf8(&FM_CLIENT_DIR));  env: "FM_MINT_CLIENT";
        FM_MINT_RPC_CLIENT: String = f!("mint-rpc-client"); env: "FM_MINT_RPC_CLIENT";
        FM_GWCLI_LND: String = f!("{gateway_cli} --rpcpassword=theresnosecondbest -a http://127.0.0.1:{FM_PORT_GW_LND}/",
            gateway_cli = crate::util::get_gateway_cli_path().join(" "),); env: "FM_GWCLI_LND";
        FM_GWCLI_LDK: String = f!("{gateway_cli} --rpcpassword=theresnosecondbest -a http://127.0.0.1:{FM_PORT_GW_LDK}/",
            gateway_cli = crate::util::get_gateway_cli_path().join(" "),); env: "FM_GWCLI_LDK";
        FM_DB_TOOL: String = f!("{fedimint_dbtool}", fedimint_dbtool = crate::util::get_fedimint_dbtool_cli_path().join(" ")); env: "FM_DB_TOOL";

        // fedimint config variables
        FM_TEST_BITCOIND_RPC: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}"); env: "FM_TEST_BITCOIND_RPC";
        FM_BITCOIN_RPC_URL: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}"); env: "FM_BITCOIN_RPC_URL";
        FM_BITCOIN_RPC_KIND: String = "bitcoind"; env: "FM_BITCOIN_RPC_KIND";
        FM_BITCOIND_URL: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}"); env: "FM_BITCOIND_URL";
        FM_BITCOIND_USERNAME: String = "bitcoin"; env: "FM_BITCOIND_USERNAME";
        FM_BITCOIND_PASSWORD: String = "bitcoin"; env: "FM_BITCOIND_PASSWORD";
        FM_DEFAULT_BITCOIN_RPC_URL: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}"); env: FM_DEFAULT_BITCOIN_RPC_URL_ENV;
        FM_DEFAULT_BITCOIN_RPC_KIND: String = "bitcoind"; env: FM_DEFAULT_BITCOIN_RPC_KIND_ENV;

        FM_ROCKSDB_WRITE_BUFFER_SIZE : String = (1 << 20).to_string(); env: "FM_ROCKSDB_WRITE_BUFFER_SIZE";
    }
}

impl Global {
    pub async fn new(
        test_dir: &Path,
        num_feds: usize,
        fed_size: usize,
        offline_nodes: usize,
        federations_base_port: Option<u16>,
    ) -> anyhow::Result<Self> {
        let federations_base_port = if let Some(federations_base_port) = federations_base_port {
            federations_base_port
        } else {
            port_alloc(
                (PORTS_PER_FEDIMINTD as usize * fed_size * num_feds)
                    .try_into()
                    .unwrap(),
            )?
        };
        let num_gateways: usize = 3;
        let gw_base_port = port_alloc(num_gateways as u16).unwrap();
        let this = Self::init(
            test_dir,
            num_feds,
            fed_size,
            offline_nodes,
            federations_base_port,
            num_gateways,
            gw_base_port,
        )
        .await?;
        Ok(this)
    }
}

declare_vars! {
    Fedimintd = (globals: &Global, federation_name: String, peer_id: PeerId, overrides: &FedimintdPeerOverrides) => {
        FM_IN_DEVIMINT: String = "1".to_string(); env: FM_IN_DEVIMINT_ENV;
        FM_BIND_P2P: String = format!("127.0.0.1:{}", overrides.p2p.port()); env: "FM_BIND_P2P";
        FM_BIND_API_WS: String = format!("127.0.0.1:{}", overrides.api.port()); env: "FM_BIND_API_WS";
        FM_BIND_API_IROH: String = format!("127.0.0.1:{}", overrides.api.port()); env: "FM_BIND_API_IROH";
        // for backwards compatibility with old versions
        FM_BIND_API: String = format!("127.0.0.1:{}", overrides.api.port()); env: "FM_BIND_API";
        FM_P2P_URL: String =  format!("fedimint://127.0.0.1:{}", overrides.p2p.port()); env: "FM_P2P_URL";
        FM_API_URL: String =  format!("ws://127.0.0.1:{}", overrides.api.port()); env: "FM_API_URL";
        FM_BIND_UI: String = format!("127.0.0.1:{}", overrides.base_port + FEDIMINTD_UI_PORT_OFFSET); env: "FM_BIND_UI";
        FM_BIND_METRICS_API: String = format!("127.0.0.1:{}", overrides.base_port + FEDIMINTD_METRICS_PORT_OFFSET); env: "FM_BIND_METRICS_API";
        FM_BIND_METRICS: String = format!("127.0.0.1:{}", overrides.base_port + FEDIMINTD_METRICS_PORT_OFFSET); env: "FM_BIND_METRICS";
        FM_DATA_DIR: PathBuf = mkdir(globals.FM_DATA_DIR.join(format!("fedimintd-{federation_name}-{peer_id}"))).await?; env: "FM_DATA_DIR";

        FM_IROH_P2P_SECRET_KEY_OVERRIDE : String = overrides.p2p.secret_key(); env: FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV;
        FM_IROH_API_SECRET_KEY_OVERRIDE : String = overrides.api.secret_key(); env: FM_IROH_API_SECRET_KEY_OVERRIDE_ENV;

        // We only need to force the current bitcoind rpc on fedimintd, other daemons take their
        // rpc settings over command-line etc. so always will use the right ones.
        FM_FORCE_BITCOIN_RPC_URL: String = f!("http://bitcoin:bitcoin@127.0.0.1:{}", globals.FM_PORT_BTC_RPC); env: FM_FORCE_BITCOIN_RPC_URL_ENV;
        FM_FORCE_BITCOIN_RPC_KIND: String = "bitcoind"; env: FM_FORCE_BITCOIN_RPC_KIND_ENV;
    }
}
