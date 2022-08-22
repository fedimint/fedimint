use bitcoincore_rpc::{Auth, RpcApi};
use bitcoind::BitcoinD;

const ENV_BITCOIND_EXE: &str = "BITCOIN_EXE";

/// New bitcoind service.
pub fn new() -> BitcoinD {
    let bitcoind_conf = {
        let mut conf = bitcoind::Conf::default();
        conf.args = vec![
            "-regtest",
            "-fallbackfee=0.0004",
            "-txindex",
            "-server",
            // username: bitcoin, password: bitcoin
            "-rpcauth=bitcoin:587d364a6911aba591fe08b61963b82d$f107c294aa10f940f24475b94dcda8d921f6b85839253ba2050043104257ab27",
            "-rpcthreads=10",
        ];
        conf.view_stdout = true;
        conf
    };
    let bitcoind_exe = std::env::var(ENV_BITCOIND_EXE)
        .ok()
        .or_else(|| bitcoind::downloaded_exe_path().ok())
        .expect("you should provide env var BITCOIND_EXEC or specifiy a bitcoind version feature");
    let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &bitcoind_conf).unwrap();

    setup(&bitcoind);

    bitcoind
}

fn setup(bitcoind: &BitcoinD) {
    // mine blocks
    let addr = bitcoind
        .client
        .get_new_address(None, None)
        .expect("failed to get addr");
    bitcoind
        .client
        .generate_to_address(101, &addr)
        .expect("failed to generate to addr");
}

pub fn make_auth() -> Auth {
    Auth::UserPass("bitcoin".to_string(), "bitcoin".to_string())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::Address;

    use crate::fixtures::{real::RealBitcoinTest, BitcoinTest};

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn real_bitcoin_test_works() {
        let bitcoind = new();

        let client_url = bitcoind.rpc_url_with_wallet("default");
        let client = ::bitcoincore_rpc::Client::new(&client_url, make_auth())
            .expect("failed to create rpc client");
        let bitcoin_test = Box::new(RealBitcoinTest::from_client(client)) as Box<dyn BitcoinTest>;

        bitcoin_test.mine_blocks(101);

        let addr = bitcoin_test.get_new_address();
        bitcoin_test.send_and_mine_block(&addr, bitcoin::Amount::from_sat(1200));

        let addr =
            Address::from_str("bcrt1q7klancfzsh3gx667t8w05cswpwp48knux8grrfl5snd9q6xpxrns0xn6ej")
                .unwrap();
        bitcoin_test.send_and_mine_block(&addr, bitcoin::Amount::from_sat(1200));
    }
}
