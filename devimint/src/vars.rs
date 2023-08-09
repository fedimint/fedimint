#![allow(non_snake_case)]

use std::path::{Path, PathBuf};

use fedimint_core::util::write_overwrite_async;

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

            pub fn vars<'a>(&'a self) -> impl Iterator<Item = (&'static str, String)> {
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
        FM_CLN_DIR: PathBuf = mkdir(FM_TEST_DIR.join("cln")).await?;
        FM_LND_DIR: PathBuf = mkdir(FM_TEST_DIR.join("lnd")).await?;
        FM_BTC_DIR: PathBuf = mkdir(FM_TEST_DIR.join("bitcoin")).await?;
        FM_DATA_DIR: PathBuf = mkdir(FM_TEST_DIR.join("cfg")).await?;
        FM_ELECTRS_DIR: PathBuf = mkdir(FM_TEST_DIR.join("electrs")).await?;
        FM_ESPLORA_DIR: PathBuf = mkdir(FM_TEST_DIR.join("esplora")).await?;
        FM_READY_FILE: PathBuf = FM_TEST_DIR.join("ready");

        FM_CLN_SOCKET: PathBuf = FM_CLN_DIR.join("regtest/lightning-rpc");
        FM_LND_RPC_ADDR: String = "http://localhost:11009";
        FM_LND_TLS_CERT: PathBuf = FM_LND_DIR.join("tls.cert");
        FM_LND_MACAROON: PathBuf = FM_LND_DIR.join("data/chain/bitcoin/regtest/admin.macaroon");

        FM_GATEWAY_DATA_DIR: PathBuf = mkdir(FM_DATA_DIR.join("gateway")).await?;
        FM_GATEWAY_LISTEN_ADDR: String = "127.0.0.1:8175";
        FM_GATEWAY_API_ADDR: String = "http://127.0.0.1:8175";
        FM_GATEWAY_PASSWORD: String = "theresnosecondbest";

        FM_CLN_EXTENSION_LISTEN_ADDRESS: String = "0.0.0.0:8177";
        FM_GATEWAY_LIGHTNING_ADDR: String = "http://localhost:8177";
        FM_FAUCET_BIND_ADDR: String = "0.0.0.0:15243";

        // clients
        FM_LIGHTNING_CLI: String = f!("lightning-cli --network regtest --lightning-dir={}", utf8(&FM_CLN_DIR));
        FM_LNCLI: String = f!("lncli -n regtest --lnddir={} --rpcserver=localhost:11009", utf8(&FM_LND_DIR));
        FM_BTC_CLIENT: String = "bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin";
        FM_MINT_CLIENT: String = f!("fedimint-cli --data-dir {}", utf8(&FM_DATA_DIR));
        FM_MINT_RPC_CLIENT: String = f!("mint-rpc-client");
        FM_GWCLI_CLN: String = f!("gateway-cli --rpcpassword=theresnosecondbest");
        FM_GWCLI_LND: String = f!("gateway-cli --rpcpassword=theresnosecondbest -a http://127.0.0.1:28175/");
        FM_DB_TOOL: String = f!("fedimint-dbtool");

        // fedimint config variables
        FM_TEST_BITCOIND_RPC: String = "http://bitcoin:bitcoin@127.0.0.1:18443";
        FM_BITCOIN_RPC_URL: String = "http://bitcoin:bitcoin@127.0.0.1:18443";
        FM_BITCOIN_RPC_KIND: String = "bitcoind";
    }
}

impl Global {
    pub async fn new(test_dir: &Path, fed_size: usize) -> anyhow::Result<Self> {
        let this = Self::init(test_dir, fed_size).await?;
        write_overwrite_async(
            this.FM_BTC_DIR.join("bitcoin.conf"),
            include_str!("cfg/bitcoin.conf"),
        )
        .await?;

        write_overwrite_async(
            this.FM_LND_DIR.join("lnd.conf"),
            include_str!("cfg/lnd.conf"),
        )
        .await?;
        write_overwrite_async(
            this.FM_CLN_DIR.join("config"),
            include_str!("cfg/lightningd.conf"),
        )
        .await?;

        write_overwrite_async(
            this.FM_ELECTRS_DIR.join("electrs.toml"),
            include_str!("cfg/electrs.toml"),
        )
        .await?;

        Ok(this)
    }
}

// We allow ranges of 10 ports for each fedimintd / dkg instance starting from
// 18173. Each port needed is incremented by 1 within this range.
//
// * `id` - ID of the server. Used to calculate port numbers.
declare_vars! {
    Fedimintd = (globals: &Global, params: ConfigGenParams) => {
        FM_BIND_P2P: String = params.local.p2p_bind.to_string();
        FM_BIND_API: String = params.local.api_bind.to_string();
        FM_P2P_URL: String = params.consensus.peers[&params.local.our_id].p2p_url.to_string();
        FM_API_URL: String = params.consensus.peers[&params.local.our_id].api_url.to_string();
        FM_BIND_METRICS_API: String = format!("127.0.0.1:{}", 3510 + params.local.our_id.to_usize());
        FM_DATA_DIR: PathBuf = mkdir(globals.FM_DATA_DIR.join(format!("server-{}", params.local.our_id.to_usize()))).await?;
    }
}
