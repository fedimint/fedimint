#![allow(non_snake_case)]

use std::path::{Path, PathBuf};

pub trait ToEnvVar {
    fn to_env_value(&self) -> Option<String>;
}

macro_rules! declare_vars {
    ($name:ident = ($($args:tt)*) =>
        {
            $($env_name:ident : $env_ty:ty = $env_value:expr;)*
        }
    ) => {
        pub struct $name {
            $(
                #[allow(unused)]
                pub $env_name: $env_ty
            ),*
        }

        impl $name {
            pub async fn init($($args)*) -> ::anyhow::Result<Self> {
                $(let $env_name: $env_ty = $env_value.into();)*
                Ok(Self {
                    $($env_name),*
                })
            }

            pub fn vars(&self) -> impl Iterator<Item = (&'static str, String)> {
                let mut env = ::std::vec::Vec::new();
                $(
                    if let Some(value) = $crate::vars::ToEnvVar::to_env_value(&self.$env_name) {
                        env.push((stringify!($env_name), value));
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
async fn mkdir(dir: PathBuf) -> anyhow::Result<PathBuf> {
    if !dir.exists() {
        tokio::fs::create_dir(&dir).await?;
    }
    Ok(dir)
}

use fedimint_portalloc::port_alloc;
use fedimint_server::config::ConfigGenParams;
use format as f;

pub fn utf8(path: &Path) -> &str {
    path.as_os_str().to_str().expect("must be valid utf8")
}

declare_vars! {
    Global = (test_dir: &Path, fed_size: usize) =>
    {
        FM_FED_SIZE: usize = fed_size;
        FM_TMP_DIR: PathBuf = mkdir(test_dir.into()).await?;
        FM_TEST_DIR: PathBuf = FM_TMP_DIR.clone();
        FM_TEST_FAST_WEAK_CRYPTO: String = "1";
        FM_LOGS_DIR: PathBuf = mkdir(FM_TEST_DIR.join("logs")).await?;

        FM_PORT_BTC_RPC: u16 = port_alloc(1)?;
        FM_PORT_BTC_P2P: u16 = port_alloc(1)?;
        FM_PORT_BTC_ZMQ_PUB_RAW_BLOCK: u16 = port_alloc(1)?;
        FM_PORT_BTC_ZMQ_PUB_RAW_TX: u16 = port_alloc(1)?;
        FM_PORT_CLN: u16 = port_alloc(1)?;
        FM_PORT_LND_LISTEN: u16 = port_alloc(1)?;
        FM_PORT_LND_RPC: u16 = port_alloc(1)?;
        FM_PORT_LND_REST: u16 = port_alloc(1)?;
        FM_PORT_ELECTRS: u16 = port_alloc(1)?;
        FM_PORT_ELECTRS_MONITORING: u16 = port_alloc(1)?;
        FM_PORT_ESPLORA: u16 = port_alloc(1)?;
        // 3 = p2p + api + metrics
        FM_PORT_FEDIMINTD_BASE: u16 = port_alloc((3 * fed_size).try_into().unwrap())?;
        FM_PORT_GW_CLN: u16 = port_alloc(1)?;
        FM_PORT_GW_LND: u16 = port_alloc(1)?;
        FM_PORT_CLN_EXTENSION: u16 = port_alloc(1)?;
        FM_PORT_FAUCET: u16 = 15243u16;

        FM_CLN_DIR: PathBuf = mkdir(FM_TEST_DIR.join("cln")).await?;
        FM_LND_DIR: PathBuf = mkdir(FM_TEST_DIR.join("lnd")).await?;
        FM_BTC_DIR: PathBuf = mkdir(FM_TEST_DIR.join("bitcoin")).await?;
        FM_DATA_DIR: PathBuf = FM_TEST_DIR.clone();
        FM_CLIENT_BASE_DIR: PathBuf = mkdir(FM_TEST_DIR.join("clients")).await?;
        FM_CLIENT_DIR: PathBuf = mkdir(FM_TEST_DIR.join("clients").join("default")).await?;
        FM_ELECTRS_DIR: PathBuf = mkdir(FM_TEST_DIR.join("electrs")).await?;
        FM_ESPLORA_DIR: PathBuf = mkdir(FM_TEST_DIR.join("esplora")).await?;
        FM_READY_FILE: PathBuf = FM_TEST_DIR.join("ready");

        FM_CLN_SOCKET: PathBuf = FM_CLN_DIR.join("regtest/lightning-rpc");
        FM_LND_RPC_ADDR: String = f!("https://localhost:{FM_PORT_LND_RPC}");
        FM_LND_TLS_CERT: PathBuf = FM_LND_DIR.join("tls.cert");
        FM_LND_MACAROON: PathBuf = FM_LND_DIR.join("data/chain/bitcoin/regtest/admin.macaroon");

        FM_GATEWAY_API_ADDR: String = f!("http://127.0.0.1:{FM_PORT_GW_CLN}");
        FM_GATEWAY_PASSWORD: String = "theresnosecondbest";
        FM_GATEWAY_FEES: String = "0,0"; // Enable to us to make an unbounded number of payments

        FM_CLN_EXTENSION_LISTEN_ADDRESS: String = f!("0.0.0.0:{FM_PORT_CLN_EXTENSION}");
        FM_GATEWAY_LIGHTNING_ADDR: String = f!("http://localhost:{FM_PORT_CLN_EXTENSION}");
        FM_FAUCET_BIND_ADDR: String = f!("0.0.0.0:{FM_PORT_FAUCET}");

        // clients
        FM_LIGHTNING_CLI: String = f!("{lightning_cli} --network regtest --lightning-dir={lightning_dir}",
            lightning_cli = crate::util::get_lightning_cli_path().join(" "),
            lightning_dir = utf8(&FM_CLN_DIR));
        FM_LNCLI: String = f!("{lncli} -n regtest --lnddir={lnddir} --rpcserver=localhost:{FM_PORT_LND_RPC}",
            lncli = crate::util::get_lncli_path().join(" "),
            lnddir = utf8(&FM_LND_DIR));
        FM_BTC_CLIENT: String = f!("{bitcoin_cli} -regtest -rpcuser=bitcoin -rpcpassword=bitcoin -datadir={datadir}",
            bitcoin_cli = crate::util::get_bitcoin_cli_path().join(" "),
            datadir = utf8(&FM_BTC_DIR));
        FM_MINT_CLIENT: String = f!("{fedimint_cli} --data-dir {datadir}",
            fedimint_cli = crate::util::get_fedimint_cli_path().join(" "),
            datadir = utf8(&FM_CLIENT_DIR));
        FM_MINT_RPC_CLIENT: String = f!("mint-rpc-client");
        FM_GWCLI_CLN: String = f!("{gateway_cli} --rpcpassword=theresnosecondbest -a http://127.0.0.1:{FM_PORT_GW_CLN}/",
            gateway_cli = crate::util::get_gateway_cli_path().join(" "),);
        FM_GWCLI_LND: String = f!("{gateway_cli} --rpcpassword=theresnosecondbest -a http://127.0.0.1:{FM_PORT_GW_LND}/",
            gateway_cli = crate::util::get_gateway_cli_path().join(" "),);
        // FIXME: create a command
        FM_DB_TOOL: String = f!("fedimint-dbtool");

        // fedimint config variables
        FM_TEST_BITCOIND_RPC: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}");
        FM_BITCOIN_RPC_URL: String = f!("http://bitcoin:bitcoin@127.0.0.1:{FM_PORT_BTC_RPC}");
        FM_BITCOIN_RPC_KIND: String = "bitcoind";

        FM_ROCKSDB_WRITE_BUFFER_SIZE : String = (1 << 20).to_string();
    }
}

impl Global {
    pub async fn new(test_dir: &Path, fed_size: usize) -> anyhow::Result<Self> {
        let this = Self::init(test_dir, fed_size).await?;
        Ok(this)
    }
}

declare_vars! {
    Fedimintd = (globals: &Global, params: ConfigGenParams) => {
        FM_BIND_P2P: String = params.local.p2p_bind.to_string();
        FM_BIND_API: String = params.local.api_bind.to_string();
        FM_P2P_URL: String = params.consensus.peers[&params.local.our_id].p2p_url.to_string();
        FM_API_URL: String = params.consensus.peers[&params.local.our_id].api_url.to_string();
        FM_BIND_METRICS_API: String = format!("127.0.0.1:{}", globals.FM_PORT_FEDIMINTD_BASE as usize + 2 * globals.FM_FED_SIZE + params.local.our_id.to_usize());
        FM_DATA_DIR: PathBuf = mkdir(globals.FM_DATA_DIR.join(format!("fedimintd-{}", params.local.our_id.to_usize()))).await?;
    }
}
