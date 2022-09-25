use crate::config::WalletConfig;
use crate::{bitcoind::BitcoindRpc, Feerate};
use async_trait::async_trait;
use bitcoin::{Block, BlockHash, Network, Transaction};
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::Auth;
use fedimint_api::module::__reexports::serde_json::Value;
use serde::Deserialize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tracing::warn;

pub fn bitcoind_gen(cfg: WalletConfig) -> impl Fn() -> Box<dyn BitcoindRpc> {
    move || -> Box<dyn BitcoindRpc> {
        let bitcoind_client = bitcoincore_rpc::Client::new(
            &cfg.btc_rpc_address,
            Auth::UserPass(cfg.btc_rpc_user.clone(), cfg.btc_rpc_pass.clone()),
        )
        .expect("Could not connect to bitcoind");
        let retry_client = RetryClient {
            client: bitcoind_client,
            retries: Default::default(),
            max_retries: 10,
            base_sleep: Duration::from_millis(10),
        };

        Box::new(retry_client)
    }
}

#[derive(Debug)]
struct RetryClient {
    client: bitcoincore_rpc::Client,
    retries: std::sync::atomic::AtomicU16,
    max_retries: u16,
    base_sleep: Duration,
}

impl bitcoincore_rpc::RpcApi for RetryClient {
    fn call<T: for<'a> Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[Value],
    ) -> bitcoincore_rpc::Result<T> {
        let mut fail_sleep = self.base_sleep;
        let ret = loop {
            match self.client.call(cmd, args) {
                Ok(ret) => {
                    break ret;
                }
                Err(e) => {
                    warn!("bitcoind returned error on cmd '{}': {}", cmd, e);
                    let retries = self.retries.fetch_add(1, Ordering::Relaxed);

                    if retries > self.max_retries {
                        return Err(e);
                    }

                    std::thread::sleep(fail_sleep);
                    fail_sleep *= 2;
                }
            }
        };
        self.retries.store(0, Ordering::Relaxed);
        Ok(ret)
    }
}

#[async_trait]
impl<T> BitcoindRpc for T
where
    T: bitcoincore_rpc::RpcApi + Send + Sync,
{
    async fn get_network(&self) -> Network {
        let network = fedimint_api::task::block_in_place(|| self.get_blockchain_info())
            .expect("Bitcoind returned an error");
        match network.chain.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            n => panic!("Unknown Network \"{}\"", n),
        }
    }

    async fn get_block_height(&self) -> u64 {
        fedimint_api::task::block_in_place(|| self.get_block_count())
            .expect("Bitcoind returned an error")
    }

    async fn get_block_hash(&self, height: u64) -> BlockHash {
        fedimint_api::task::block_in_place(|| bitcoincore_rpc::RpcApi::get_block_hash(self, height))
            .expect("Bitcoind returned an error")
    }

    async fn get_block(&self, hash: &BlockHash) -> Block {
        fedimint_api::task::block_in_place(|| bitcoincore_rpc::RpcApi::get_block(self, hash))
            .expect("Bitcoind returned an error")
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Option<Feerate> {
        fedimint_api::task::block_in_place(|| {
            self.estimate_smart_fee(confirmation_target, Some(EstimateMode::Conservative))
        })
        .expect("Bitcoind returned an error") // TODO: implement retry logic in case bitcoind is temporarily unreachable
        .fee_rate
        .map(|per_kb| Feerate {
            sats_per_kvb: per_kb.as_sat(),
        })
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        if let Err(error) =
            fedimint_api::task::block_in_place(|| self.send_raw_transaction(&transaction))
        {
            warn!(?error, "Submitting transaction failed");
        }
    }
}
