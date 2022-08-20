use crate::config::WalletConfig;
use crate::{bitcoind::BitcoindRpc, Feerate};
use async_trait::async_trait;
use bitcoin::{Block, BlockHash, Network, Transaction};
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::{Auth, RpcApi};
use tracing::warn;

pub fn bitcoind_gen(cfg: WalletConfig) -> impl Fn() -> Box<dyn BitcoindRpc> {
    move || -> Box<dyn BitcoindRpc> {
        Box::new(
            bitcoincore_rpc::Client::new(
                &cfg.btc_rpc_address,
                Auth::UserPass(cfg.btc_rpc_user.clone(), cfg.btc_rpc_pass.clone()),
            )
            .expect("Could not connect to bitcoind"),
        )
    }
}

#[async_trait]
impl BitcoindRpc for bitcoincore_rpc::Client {
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
