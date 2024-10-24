#![allow(non_snake_case)]

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use fedimint_core::envs::FM_ENABLE_MODULE_LNV2_ENV;

pub trait ToEnvVar {
    fn to_env_value(&self) -> Option<String>;
}

macro_rules! declare_vars {
    ($struct:ident = ($($args:tt)*) =>
        {
            $($name:ident : $ty:ty = $value:expr; env: $env:expr;)*
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

            pub fn vars(&self) -> impl Iterator<Item = (&'static str, String)> {
                let mut env = ::std::vec::Vec::new();
                $(
                    if let Some(value) = $crate::vars::ToEnvVar::to_env_value(&self.$name) {
                        env.push(($env, value));
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
    FM_FORCE_BITCOIN_RPC_URL_ENV, FM_IN_DEVIMINT_ENV, FM_USE_UNKNOWN_MODULE_ENV,
};
use fedimint_portalloc::port_alloc;
use fedimint_server::config::ConfigGenParams;
use fedimint_server::net::api::ApiSecrets;
use fedimintd::envs::FM_FORCE_API_SECRETS_ENV;
use format as f;

pub fn utf8(path: &Path) -> &str {
    path.as_os_str().to_str().expect("must be valid utf8")
}

declare_vars! {
    Global = (test_dir: &Path, fed_size: usize, offline_nodes: usize) =>
    {
        FM_USE_UNKNOWN_MODULE: String = std::env::var(FM_USE_UNKNOWN_MODULE_ENV).unwrap_or_else(|_| "1".into()); env: "FM_USE_UNKNOWN_MODULE";
        FM_ENABLE_MODULE_LNV2: String = std::env::var(FM_ENABLE_MODULE_LNV2_ENV).unwrap_or_else(|_| "1".into()); env: "FM_ENABLE_MODULE_LNV2";


        FM_FORCE_API_SECRETS: ApiSecrets = std::env::var(FM_FORCE_API_SECRETS_ENV).ok().and_then(|s| {
            ApiSecrets::from_str(&s).ok()
        }).unwrap_or_default(); env: FM_FORCE_API_SECRETS_ENV;

        FM_API_SECRET: Option<String> = std::env::var("FM_API_SECRET").ok().or_else(|| FM_FORCE_API_SECRETS.get_active()); env: "FM_API_SECRET";

        FM_IN_DEVIMINT: String = "1".to_string(); env: FM_IN_DEVIMINT_ENV;
        FM_SKIP_REL_NOTES_ACK: String = "1".to_string(); env: "FM_SKIP_REL_NOTES_ACK";

        FM_FED_SIZE: usize = fed_size; env: "FM_FED_SIZE";
        FM_OFFLINE_NODES: usize = offline_nodes; env: "FM_OFFLINE_NODES";
        FM_TMP_DIR: PathBuf = mkdir(test_dir.into()).await?; env: "FM_TMP_DIR";
        FM_TEST_DIR: PathBuf = FM_TMP_DIR.clone(); env: "FM_TEST_DIR";
        FM_TEST_FAST_WEAK_CRYPTO: String = "1"; env: "FM_TEST_FAST_WEAK_CRYPTO";
        FM_LOGS_DIR: PathBuf = mkdir(FM_TEST_DIR.join("logs")).await?; env: "FM_LOGS_DIR";

        FM_PORT_BTC_RPC: u16 = port_alloc(1)?; env: "FM_PORT_BTC_RPC";
        FM_PORT_BTC_P2P: u16 = port_alloc(1)?; env: "FM_PORT_BTC_P2P";
        FM_PORT_BTC_ZMQ_PUB_RAW_BLOCK: u16 = port_alloc(1)?; env: "FM_PORT_BTC_ZMQ_PUB_RAW_BLOCK";
        FM_PORT_BTC_ZMQ_PUB_RAW_TX: u16 = port_alloc(1)?; env: "FM_PORT_BTC_ZMQ_PUB_RAW_TX";
        FM_PORT_CLN: u16 = port_alloc(1)?; env: "FM_PORT_CLN";
        FM_PORT_LND_LISTEN: u16 = port_alloc(1)?; env: "FM_PORT_LND_LISTEN";
        FM_PORT_LDK: u16 = port_alloc(1)?; env: "FM_PORT_LDK";
        FM_PORT_LND_RPC: u16 = port_alloc(1)?; env: "FM_PORT_LND_RPC";
        FM_PORT_LND_REST: u16 = port_alloc(1)?; env: "FM_PORT_LND_REST";
        FM_PORT_ELECTRS: u16 = port_alloc(1)?; env: "FM_PORT_ELECTRS";
        FM_PORT_ELECTRS_MONITORING: u16 = port_alloc(1)?; env: "FM_PORT_ELECTRS_MONITORING";
        FM_PORT_ESPLORA: u16 = port_alloc(1)?; env: "FM_PORT_ESPLORA";
        // 3 = p2p + api + metrics env: "// ";
        FM_PORT_FEDIMINTD_BASE: u16 = port_alloc((3 * fed_size).try_into().unwrap())?; env: "FM_PORT_FEDIMINTD_BASE";
        FM_PORT_GW_CLN: u16 = port_alloc(1)?; env: "FM_PORT_GW_CLN";
        FM_PORT_GW_LND: u16 = port_alloc(1)?; env: "FM_PORT_GW_LND";
        FM_PORT_GW_LDK: u16 = port_alloc(1)?; env: "FM_PORT_GW_LDK";
        FM_PORT_CLN_EXTENSION: u16 = port_alloc(1)?; env: "FM_PORT_CLN_EXTENSION";
        FM_PORT_FAUCET: u16 = 15243u16; env: "FM_PORT_FAUCET";

        FM_LDK_ESPLORA_SERVER_URL: String = format!("http://127.0.0.1:{FM_PORT_ESPLORA}"); env: "FM_LDK_ESPLORA_SERVER_URL";

        FM_CLN_DIR: PathBuf = mkdir(FM_TEST_DIR.join("cln")).await?; env: "FM_CLN_DIR";
        FM_LND_DIR: PathBuf = mkdir(FM_TEST_DIR.join("lnd")).await?; env: "FM_LND_DIR";
        FM_LDK_DIR: PathBuf = mkdir(FM_TEST_DIR.join("ldk")).await?; env: "FM_LDK_DIR";
        FM_BTC_DIR: PathBuf = mkdir(FM_TEST_DIR.join("bitcoin")).await?; env: "FM_BTC_DIR";
        FM_DATA_DIR: PathBuf = FM_TEST_DIR.clone(); env: "FM_DATA_DIR";
        FM_CLIENT_BASE_DIR: PathBuf = mkdir(FM_TEST_DIR.join("clients")).await?; env: "FM_CLIENT_BASE_DIR";
        FM_CLIENT_DIR: PathBuf = mkdir(FM_TEST_DIR.join("clients").join("default-0")).await?; env: "FM_CLIENT_DIR";
        FM_ELECTRS_DIR: PathBuf = mkdir(FM_TEST_DIR.join("electrs")).await?; env: "FM_ELECTRS_DIR";
        FM_ESPLORA_DIR: PathBuf = mkdir(FM_TEST_DIR.join("esplora")).await?; env: "FM_ESPLORA_DIR";
        FM_READY_FILE: PathBuf = FM_TEST_DIR.join("ready"); env: "FM_READY_FILE";

        FM_CLN_SOCKET: PathBuf = FM_CLN_DIR.join("regtest/lightning-rpc"); env: "FM_CLN_SOCKET";
        FM_LND_RPC_ADDR: String = f!("https://localhost:{FM_PORT_LND_RPC}"); env: "FM_LND_RPC_ADDR";
        FM_LND_TLS_CERT: PathBuf = FM_LND_DIR.join("tls.cert"); env: "FM_LND_TLS_CERT";
        FM_LND_MACAROON: PathBuf = FM_LND_DIR.join("data/chain/bitcoin/regtest/admin.macaroon"); env: "FM_LND_MACAROON";

        FM_GATEWAY_API_ADDR: String = f!("http://127.0.0.1:{FM_PORT_GW_CLN}"); env: "FM_GATEWAY_API_ADDR";
        FM_GATEWAY_PASSWORD: String = "theresnosecondbest"; env: "FM_GATEWAY_PASSWORD";

         // Enable to us to make an unbounded number of payments
        FM_DEFAULT_GATEWAY_FEES: String = "0,0"; env: "FM_DEFAULT_GATEWAY_FEES";
        FM_GATEWAY_SKIP_WAIT_FOR_SYNC: String = "1"; env: "FM_GATEWAY_SKIP_WAIT_FOR_SYNC";

        FM_CLN_EXTENSION_LISTEN_ADDRESS: String = f!("0.0.0.0:{FM_PORT_CLN_EXTENSION}"); env: "FM_CLN_EXTENSION_LISTEN_ADDRESS";
        FM_GATEWAY_LIGHTNING_ADDR: String = f!("http://localhost:{FM_PORT_CLN_EXTENSION}"); env: "FM_GATEWAY_LIGHTNING_ADDR";
        FM_FAUCET_BIND_ADDR: String = f!("0.0.0.0:{FM_PORT_FAUCET}"); env: "FM_FAUCET_BIND_ADDR";

        // clients env: "// ";
        FM_LIGHTNING_CLI: String = f!("{lightning_cli} --network regtest --lightning-dir={lightning_dir}",
            lightning_cli = crate::util::get_lightning_cli_path().join(" "),
            lightning_dir = utf8(&FM_CLN_DIR)); env: "FM_LIGHTNING_CLI";
        FM_LNCLI: String = f!("{lncli} -n regtest --lnddir={lnddir} --rpcserver=localhost:{FM_PORT_LND_RPC}",
            lncli = crate::util::get_lncli_path().join(" "),
            lnddir = utf8(&FM_LND_DIR)); env: "FM_LNCLI";
        FM_BTC_CLIENT: String = f!("{bitcoin_cli} -regtest -rpcuser=bitcoin -rpcpassword=bitcoin -datadir={datadir}",             bitcoin_cli = crate::util::get_bitcoin_cli_path().join(" "),
            datadir = utf8(&FM_BTC_DIR)); env: "FM_BTC_CLIENT";

        FM_MINT_CLIENT: String = f!("{fedimint_cli} --data-dir {datadir}",
            fedimint_cli = crate::util::get_fedimint_cli_path().join(" "),
            datadir = utf8(&FM_CLIENT_DIR));  env: "FM_MINT_CLIENT";
        FM_MINT_RPC_CLIENT: String = f!("mint-rpc-client"); env: "FM_MINT_RPC_CLIENT";
        FM_GWCLI_CLN: String = f!("{gateway_cli} --rpcpassword=theresnosecondbest -a http://127.0.0.1:{FM_PORT_GW_CLN}/",
            gateway_cli = crate::util::get_gateway_cli_path().join(" "),); env: "FM_GWCLI_CLN";
        FM_GWCLI_LND: String = f!("{gateway_cli} --rpcpassword=theresnosecondbest -a http://127.0.0.1:{FM_PORT_GW_LND}/",
            gateway_cli = crate::util::get_gateway_cli_path().join(" "),); env: "FM_GWCLI_LND";
        FM_GWCLI_LDK: String = f!("{gateway_cli} --rpcpassword=theresnosecondbest -a http://127.0.0.1:{FM_PORT_GW_LDK}/",
            gateway_cli = crate::util::get_gateway_cli_path().join(" "),); env: "FM_GWCLI_LDK";
        FM_DB_TOOL: String = f!("{fedimint_dbtool}", fedimint_dbtool = crate::util::get_fedimint_dbtool_cli_path().join(" ")); env: "FM_DB_TOOL";

        // fedimint config variables
        FM_TEST_BITCOIND_RPC: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}"); env: "FM_TEST_BITCOIND_RPC";
        FM_BITCOIN_RPC_URL: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}"); env: "FM_BITCOIN_RPC_URL";
        FM_BITCOIN_RPC_KIND: String = "bitcoind"; env: "FM_BITCOIN_RPC_KIND";
        FM_DEFAULT_BITCOIN_RPC_URL: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}"); env: FM_DEFAULT_BITCOIN_RPC_URL_ENV;
        FM_DEFAULT_BITCOIN_RPC_KIND: String = "bitcoind"; env: FM_DEFAULT_BITCOIN_RPC_KIND_ENV;

        FM_ROCKSDB_WRITE_BUFFER_SIZE : String = (1 << 20).to_string(); env: "FM_ROCKSDB_WRITE_BUFFER_SIZE";
    }
}

impl Global {
    pub async fn new(
        test_dir: &Path,
        fed_size: usize,
        offline_nodes: usize,
    ) -> anyhow::Result<Self> {
        let this = Self::init(test_dir, fed_size, offline_nodes).await?;
        Ok(this)
    }
}

declare_vars! {
    Fedimintd = (globals: &Global, params: ConfigGenParams, federation_name: String, base_port: u16) => {
        FM_BIND_P2P: String = params.local.p2p_bind.to_string(); env: "FM_BIND_P2P";
        FM_BIND_API: String = params.local.api_bind.to_string(); env: "FM_BIND_API";
        FM_P2P_URL: String = params.consensus.peers[&params.local.our_id].p2p_url.to_string(); env: "FM_P2P_URL";
        FM_API_URL: String = params.consensus.peers[&params.local.our_id].api_url.to_string(); env: "FM_API_URL";
        FM_BIND_METRICS_API: String = format!("127.0.0.1:{}", base_port as usize + 2 * globals.FM_FED_SIZE + params.local.our_id.to_usize()); env: "FM_BIND_METRICS_API";
        FM_DATA_DIR: PathBuf = mkdir(globals.FM_DATA_DIR.join(format!("fedimintd-{}-{}", federation_name, params.local.our_id.to_usize()))).await?; env: "FM_DATA_DIR";

        // We only need to force the current bitcoind rpc on fedimintd, other daemons take their
        // rpc settings over command-line etc. so always will use the right ones.
        FM_FORCE_BITCOIN_RPC_URL: String = f!("http://bitcoin:bitcoin@127.0.0.1:{}", globals.FM_PORT_BTC_RPC); env: FM_FORCE_BITCOIN_RPC_URL_ENV;
        FM_FORCE_BITCOIN_RPC_KIND: String = "bitcoind"; env: FM_FORCE_BITCOIN_RPC_KIND_ENV;
    }
}
