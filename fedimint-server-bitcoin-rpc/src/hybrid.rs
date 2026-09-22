#[cfg(test)]
mod tests;

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use bitcoin::{BlockHash, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::LOG_SERVER;
use fedimint_server_core::bitcoin_rpc::{DynServerBitcoinRpc, IServerBitcoinRpc};
use tracing::{info, warn};

use crate::bitcoind::BitcoindClient;
use crate::esplora::EsploraClient;

/// A local bitcoind primary and trusted Esplora fallback on one chain.
///
/// Esplora is trusted for chain selection, including startup without bitcoind.
/// A one-time startup equality check catches misconfiguration when both
/// endpoints are available; it is not SPV or reconnection verification.
/// Reads remain bitcoind-first, except block counts use Esplora while Core
/// explicitly reports initial block download. Broadcast remains primary-first.
#[derive(Debug)]
pub struct BitcoindClientWithFallback {
    /// Primary full-node RPC.
    bitcoind_client: DynServerBitcoinRpc,
    /// Trusted fallback RPC.
    esplora_client: DynServerBitcoinRpc,
    /// First chain identity obtained during startup or ordinary status reads.
    chain_id: OnceLock<ChainId>,
    /// Whether Core has reported completion of initial block download.
    bitcoind_ibd_complete: AtomicBool,
}

impl BitcoindClientWithFallback {
    /// Construct and initialize a hybrid backend using two trusted endpoints.
    pub async fn new(
        username: String,
        password: String,
        bitcoind_url: &SafeUrl,
        esplora_url: &SafeUrl,
    ) -> Result<Self> {
        info!(
            target: LOG_SERVER,
            %bitcoind_url,
            %esplora_url,
            "Initializing bitcoin bitcoind backend with trusted esplora fallback"
        );
        Self::from_clients(
            BitcoindClient::new(username, password, bitcoind_url)?.into_dyn(),
            EsploraClient::new(esplora_url)?.into_dyn(),
        )
        .await
    }

    /// Perform the one-time startup identity check and build the backend.
    async fn from_clients(
        bitcoind_client: DynServerBitcoinRpc,
        esplora_client: DynServerBitcoinRpc,
    ) -> Result<Self> {
        let (primary, fallback) = tokio::join!(
            bitcoind_client.get_chain_id(),
            esplora_client.get_chain_id(),
        );
        let chain_id = match (primary, fallback) {
            (Ok(primary), Ok(fallback)) => {
                if primary != fallback {
                    return Err(anyhow!("Bitcoind and Esplora chain identities differ"));
                }
                Some(primary)
            }
            (Ok(chain_id), Err(_)) => {
                warn!(
                    target: LOG_SERVER,
                    "Could not compare Esplora chain identity at startup; using bitcoind identity"
                );
                Some(chain_id)
            }
            (Err(_), Ok(chain_id)) => {
                warn!(
                    target: LOG_SERVER,
                    "Could not compare bitcoind chain identity at startup; using trusted Esplora identity"
                );
                Some(chain_id)
            }
            (Err(_), Err(_)) => {
                warn!(
                    target: LOG_SERVER,
                    "Could not check either Bitcoin backend chain identity at startup"
                );
                None
            }
        };
        let cached_chain_id = OnceLock::new();
        if let Some(chain_id) = chain_id {
            let _ = cached_chain_id.set(chain_id);
        }
        Ok(Self {
            bitcoind_client,
            esplora_client,
            chain_id: cached_chain_id,
            bitcoind_ibd_complete: AtomicBool::new(false),
        })
    }

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

/// Try an ordinary read locally, then retry only that request on Esplora.
macro_rules! read_rpc {
    ($self:ident, $method:ident $(, $arg:expr)*) => {{
        let primary = $self.bitcoind_client.$method($($arg),*).await;
        match primary {
            Ok(value) => Ok(value),
            Err(primary) => {
                warn!(
                    target: LOG_SERVER,
                    method = stringify!($method),
                    error = %primary.fmt_compact_anyhow(),
                    "Bitcoind read failed; trying Esplora"
                );
                match $self.esplora_client.$method($($arg),*).await {
                    Ok(value) => Ok(value),
                    Err(_) => {
                        warn!(
                            target: LOG_SERVER,
                            method = stringify!($method),
                            "Esplora read fallback also failed; returning the bitcoind error"
                        );
                        Err(primary)
                    }
                }
            }
        }
    }};
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
        read_rpc!(self, get_block_hash, height)
    }

    async fn get_block(&self, block_hash: &BlockHash) -> Result<bitcoin::Block> {
        read_rpc!(self, get_block, block_hash)
    }

    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        read_rpc!(self, get_feerate)
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        match self
            .bitcoind_client
            .submit_transaction(transaction.clone())
            .await
        {
            Ok(()) => Ok(()),
            Err(primary) => {
                warn!(target: LOG_SERVER, error = %primary.fmt_compact_anyhow(), "Bitcoind broadcast failed; trying Esplora");
                match self.esplora_client.submit_transaction(transaction).await {
                    Ok(()) => Ok(()),
                    Err(_) => {
                        warn!(
                            target: LOG_SERVER,
                            "Esplora broadcast fallback also failed; returning the bitcoind error"
                        );
                        Err(primary)
                    }
                }
            }
        }
    }

    async fn get_sync_progress(&self) -> Result<Option<f64>> {
        Ok(None)
    }

    async fn get_chain_id(&self) -> Result<ChainId> {
        if let Some(chain_id) = self.chain_id.get() {
            return Ok(*chain_id);
        }

        let chain_id = match self.bitcoind_client.get_chain_id().await {
            Ok(chain_id) => chain_id,
            Err(primary) => {
                warn!(
                    target: LOG_SERVER,
                    error = %primary.fmt_compact_anyhow(),
                    "Bitcoind chain identity unavailable; trying Esplora"
                );
                self.esplora_client.get_chain_id().await?
            }
        };
        let _ = self.chain_id.set(chain_id);
        Ok(*self
            .chain_id
            .get()
            .expect("chain identity was just initialized"))
    }
}
