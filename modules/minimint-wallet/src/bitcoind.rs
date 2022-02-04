use crate::Feerate;
use async_trait::async_trait;
use bitcoin::{BlockHash, Network, Transaction};
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::RpcApi;
use tracing::warn;

/// Trait that allows interacting with the Bitcoin blockchain
#[async_trait]
pub trait BitcoindRpc: Send + Sync {
    /// Returns the Bitcoin network the node is connected to
    async fn get_network(&self) -> bitcoin::Network;

    /// Returns the current block height
    async fn get_block_height(&self) -> u64;

    /// Returns the block hash at a given height
    ///
    /// # Panics
    /// If the node does not know a block for that height. Make sure to only query blocks of a
    /// height less or equal to the one returned by `Self::get_block_height`.
    ///
    /// While there is a corner case that the blockchain shrinks between these two calls (through on
    /// average heavier blocks on a fork) this is prevented by only querying hashes for blocks
    /// tailing the chain tip by a certain number of blocks.
    async fn get_block_hash(&self, height: u64) -> BlockHash;

    /// Estimates the fee rate for a given confirmation target. Make sure that all federation
    /// members use the same algorithm to avoid widely diverging results. If the node is not ready
    /// yet to return a fee rate estimation this function returns `None`.
    async fn get_fee_rate(&self, confirmation_target: u16) -> Option<Feerate>;

    /// Submits a transaction to the Bitcoin network
    ///
    /// # Panics
    /// If the transaction is deemed invalid by the node it was submitted to
    async fn submit_transaction(&self, transaction: Transaction);
}

#[async_trait]
impl BitcoindRpc for bitcoincore_rpc::Client {
    async fn get_network(&self) -> Network {
        let network = tokio::task::block_in_place(|| self.get_blockchain_info())
            .expect("Bitcoind returned an error");
        match network.chain.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => panic!("Unknown Network"),
        }
    }

    async fn get_block_height(&self) -> u64 {
        tokio::task::block_in_place(|| self.get_block_count()).expect("Bitcoind returned an error")
    }

    async fn get_block_hash(&self, height: u64) -> BlockHash {
        tokio::task::block_in_place(|| bitcoincore_rpc::RpcApi::get_block_hash(self, height))
            .expect("Bitcoind returned an error")
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Option<Feerate> {
        tokio::task::block_in_place(|| {
            self.estimate_smart_fee(confirmation_target, Some(EstimateMode::Conservative))
        })
        .expect("Bitcoind returned an error") // TODO: implement retry logic in case bitcoind is temporarily unreachable
        .fee_rate
        .map(|per_kb| Feerate {
            sats_per_kvb: per_kb.as_sat(),
        })
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        if let Err(e) = tokio::task::block_in_place(|| self.send_raw_transaction(&transaction)) {
            warn!("Submitting transaction failed: {:?}", e);
        }
    }
}
