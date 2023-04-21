#![allow(non_snake_case)]
#![allow(dead_code)]

macro_rules! declare_vars {
    // mini nix :)
    ($name:ident = {$($args:tt)*}:
        $(let $($bind:ident = $bind_value:expr;)*
            in)?
        {
            $($env_name:ident = $env_value:expr;)*
        }
    ) => {
        pub struct $name {
            $(
        $env_name: String
    ),*
        }

        impl $name {
            // TODO: add async if needed
            pub fn new($($args)*) -> Self {
                $($(let $bind = $bind_value;)*)?
                $(let $env_name = ::std::borrow::Cow::from($env_value).into_owned();)*
                Self {
                    $($env_name),*
                }
            }
            pub fn vars<'a>(&'a self, $($args)*) -> impl Iterator<Item = (&'static str, &'a str)> {
                [].into_iter() // FIXME
            }
        }
    }
}

fn mkdir(dir: String) -> String {
    todo!()
}

use format as f;
declare_vars! {
    Vars = {fed_size: usize}:
    {
        FM_FED_SIZE = f!("{fed_size}");
        FM_TMP_DIR = "/tmp/TODO";
        FM_TEST_FAST_WEAK_CRYPTO = "1";
        FM_POLL_INTERVAL = "1";
        FM_TEST_DIR = &FM_TMP_DIR;

        // FM_BIN_DIR="$SRC_DIR/target/${CARGO_PROFILE:-debug}"
        FM_LOGS_DIR = mkdir(f!("{FM_TEST_DIR}/logs"));
        FM_CLN_DIR = mkdir(f!("{FM_TEST_DIR}/cln"));
        FM_LND_DIR = mkdir(f!("{FM_TEST_DIR}/lnd"));
        FM_BTC_DIR = mkdir(f!("{FM_TEST_DIR}/bitcoin"));
        FM_DATA_DIR = mkdir(f!("{FM_TEST_DIR}/cfg"));
        FM_ELECTRS_DIR = mkdir(f!("{FM_TEST_DIR}/electrs"));
        FM_ESPLORA_DIR = mkdir(f!("{FM_TEST_DIR}/esplora"));

        FM_LND_RPC_ADDR = "http://localhost:11009";
        FM_LND_TLS_CERT = f!("{FM_LND_DIR}/tls.cert");
        FM_LND_MACAROON = f!("{FM_LND_DIR}/data/chain/bitcoin/regtest/admin.macaroon");

        FM_GATEWAY_DATA_DIR = mkdir(f!("{FM_DATA_DIR}/gateway"));
        FM_GATEWAY_LISTEN_ADDR = "127.0.0.1:8175";
        FM_GATEWAY_API_ADDR = "http://127.0.0.1:8175";
        FM_GATEWAY_PASSWORD = "theresnosecondbest";

        FM_CLN_EXTENSION_LISTEN_ADDRESS = "0.0.0.0:8177";
        FM_GATEWAY_LIGHTNING_ADDR = "http://localhost:8177";

        // clients
        FM_LIGHTNING_CLI = f!("lightning-cli --network regtest --lightning-dir={FM_CLN_DIR}");
        FM_LNCLI = f!("lncli -n regtest --lnddir={FM_LND_DIR} --rpcserver=localhost:11009");
        FM_BTC_CLIENT = "bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin";
        FM_MINT_CLIENT = f!("fedimint-cli --data-dir {FM_DATA_DIR}");
        FM_MINT_RPC_CLIENT = f!("mint-rpc-client");
        FM_GWCLI_CLN = f!("gateway-cli --rpcpassword=theresnosecondbest");
        FM_GWCLI_LND = f!("gateway-cli --rpcpassword=theresnosecondbest -a http://127.0.0.1:28175/");
        FM_DB_TOOL = f!("dbtool");
        FM_DISTRIBUTEDGEN = f!("distributedgen");

        // fedimint config variables
        FM_TEST_BITCOIND_RPC = "http://bitcoin:bitcoin@127.0.0.1:18443";
        FM_BITCOIND_RPC = "http://bitcoin:bitcoin@127.0.0.1:18443";
    }
}
