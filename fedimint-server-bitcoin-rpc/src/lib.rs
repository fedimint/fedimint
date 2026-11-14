pub mod bitcoind;
pub mod esplora;
pub mod metrics;
pub mod tracked;

#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use bitcoin::{BlockHash, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::{FmtCompactAnyhow, SafeUrl};
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::LOG_SERVER;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::warn;

use crate::bitcoind::BitcoindClient;
use crate::esplora::EsploraClient;

/// A Core-first backend using trusted Esplora for failed reads and IBD counts.
#[derive(Debug)]
pub struct BitcoindClientWithFallback {
    /// Primary full-node RPC.
    bitcoind_client: BitcoindClient,
    /// Operator-configured trusted fallback.
    esplora_client: EsploraClient,
    /// Whether Core has reported completion of IBD during this process
    /// lifetime.
    bitcoind_ibd_complete: AtomicBool,
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
            bitcoind_ibd_complete: AtomicBool::new(false),
        })
    }

    /// Use the trusted fallback without accepting Core's incomplete IBD count.
    async fn fallback_block_count(&self, primary: anyhow::Error) -> Result<u64> {
        warn!(
            target: LOG_SERVER,
            error = %primary.fmt_compact_anyhow(),
            "Bitcoind block count unavailable; falling back to Esplora"
        );
        match self.esplora_client.get_block_count().await {
            Ok(count) => Ok(count),
            Err(_) => {
                warn!(
                    target: LOG_SERVER,
                    "Esplora block-count fallback also failed; returning the bitcoind error"
                );
                Err(primary)
            }
        }
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
        // Match the newer hybrid policy: check IBD until its first completion,
        // then keep Core-first reads. Do not compare tips or switch on mere lag.
        if self.bitcoind_ibd_complete.load(Ordering::Relaxed) {
            return match self.bitcoind_client.get_block_count().await {
                Ok(count) => Ok(count),
                Err(primary) => self.fallback_block_count(primary).await,
            };
        }

        match self
            .bitcoind_client
            .get_block_count_and_initial_block_download()
            .await
        {
            Ok((_count, true)) => {
                self.fallback_block_count(anyhow!("Bitcoind is in initial block download"))
                    .await
            }
            Ok((count, false)) => {
                self.bitcoind_ibd_complete.store(true, Ordering::Relaxed);
                Ok(count)
            }
            Err(primary) => self.fallback_block_count(primary).await,
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

    // Missing Core estimates also use the existing Esplora policy (including its
    // 1 sat/vB floor for an empty successful response). If Esplora fails, retain
    // Core's original absence or error.
    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        match self.bitcoind_client.get_feerate().await {
            Ok(Some(feerate)) => Ok(Some(feerate)),
            Ok(None) => {
                warn!(
                    target: LOG_SERVER,
                    "Bitcoind fee estimate unavailable; trying Esplora"
                );
                match self.esplora_client.get_feerate().await {
                    Ok(feerate) => Ok(feerate),
                    Err(_) => {
                        warn!(
                            target: LOG_SERVER,
                            "Esplora fee-estimate fallback failed; retaining the unavailable bitcoind estimate"
                        );
                        Ok(None)
                    }
                }
            }
            Err(primary) => {
                warn!(
                    target: LOG_SERVER,
                    error = %primary.fmt_compact_anyhow(),
                    "Bitcoind fee-estimate request failed; trying Esplora"
                );
                match self.esplora_client.get_feerate().await {
                    Ok(feerate) => Ok(feerate),
                    Err(_) => {
                        warn!(
                            target: LOG_SERVER,
                            "Esplora fee-estimate fallback also failed; returning the bitcoind error"
                        );
                        Err(primary)
                    }
                }
            }
        }
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        match self
            .bitcoind_client
            .submit_transaction(transaction.clone())
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!(
                    target: LOG_SERVER,
                    error = %e.fmt_compact_anyhow(),
                    "BitcoindClient failed for submit_transaction, falling back to EsploraClient"
                );
                self.esplora_client.submit_transaction(transaction).await
            }
        }
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
