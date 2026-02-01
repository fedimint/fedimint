pub mod bitcoind;
pub mod esplora;

use anyhow::Result;
use bitcoin::{BlockHash, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::{FmtCompactAnyhow, SafeUrl};
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::LOG_SERVER;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::warn;

use crate::bitcoind::BitcoindClient;
use crate::esplora::EsploraClient;

#[derive(Debug)]
pub struct BitcoindClientWithFallback {
    bitcoind_client: BitcoindClient,
    esplora_client: EsploraClient,
}

impl BitcoindClientWithFallback {
    pub fn new(
        username: String,
        password: String,
        bitcoind_url: &SafeUrl,
        esplora_url: &SafeUrl,
    ) -> Result<Self> {
        warn!(
            target: LOG_SERVER,
            %bitcoind_url,
            %esplora_url,
            "Initializing bitcoin bitcoind backend with esplora fallback"
        );
        let bitcoind_client = BitcoindClient::new(username, password, bitcoind_url)?;
        let esplora_client = EsploraClient::new(esplora_url)?;

        Ok(Self {
            bitcoind_client,
            esplora_client,
        })
    }
}

#[async_trait::async_trait]
impl IServerBitcoinRpc for BitcoindClientWithFallback {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        self.bitcoind_client.get_bitcoin_rpc_config()
    }

    fn get_url(&self) -> SafeUrl {
        self.bitcoind_client.get_url()
    }

    async fn get_block_count(&self) -> Result<u64> {
        match self.bitcoind_client.get_block_count().await {
            Ok(count) => Ok(count),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    "BitcoindClient failed for get_block_count, falling back to EsploraClient"
                );
                self.esplora_client.get_block_count().await
            }
        }
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        match self.bitcoind_client.get_block_hash(height).await {
            Ok(hash) => Ok(hash),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    height = height,
                    "BitcoindClient failed for get_block_hash, falling back to EsploraClient"
                );
                self.esplora_client.get_block_hash(height).await
            }
        }
    }

    async fn get_block(&self, block_hash: &BlockHash) -> Result<bitcoin::Block> {
        match self.bitcoind_client.get_block(block_hash).await {
            Ok(block) => Ok(block),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    block_hash = %block_hash,
                    "BitcoindClient failed for get_block, falling back to EsploraClient"
                );
                self.esplora_client.get_block(block_hash).await
            }
        }
    }

    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        match self.bitcoind_client.get_feerate().await {
            Ok(feerate) => Ok(feerate),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    "BitcoindClient failed for get_feerate, falling back to EsploraClient"
                );
                self.esplora_client.get_feerate().await
            }
        }
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        // Since this endpoint does not return an error, we can just always broadcast to
        // both places
        self.bitcoind_client
            .submit_transaction(transaction.clone())
            .await;
        self.esplora_client.submit_transaction(transaction).await;
    }

    async fn get_sync_progress(&self) -> Result<Option<f64>> {
        // We're always in sync, just like esplora
        self.esplora_client.get_sync_progress().await
    }

    async fn get_chain_id(&self) -> Result<ChainId> {
        match self.bitcoind_client.get_chain_id().await {
            Ok(chain_id) => Ok(chain_id),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    "BitcoindClient failed for get_chain_id, falling back to EsploraClient"
                );
                self.esplora_client.get_chain_id().await
            }
        }
    }
}
