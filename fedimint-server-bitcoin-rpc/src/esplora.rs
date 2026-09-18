#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use anyhow::{Context, ensure};
use bitcoin::{BlockHash, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::SafeUrl;
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::LOG_SERVER;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::info;

const ESPLORA_CLIENT_TIMEOUT_SECONDS: u64 = 60;

/// Check payload integrity against the caller's requested header hash.
///
/// This does not validate chain selection or proof of work: the configured
/// Esplora server remains a trusted source of block hashes.
fn validate_block(block: bitcoin::Block, requested: &BlockHash) -> anyhow::Result<bitcoin::Block> {
    ensure!(
        block.block_hash() == *requested,
        "Esplora returned a different block"
    );
    ensure!(
        block.check_merkle_root(),
        "Esplora returned an invalid transaction merkle root"
    );
    // Merkle roots alone permit mutation by duplicating the final subtree.
    // A valid block cannot repeat a txid, so reject all duplicate transactions.
    let mut txids = HashSet::with_capacity(block.txdata.len());
    ensure!(
        block
            .txdata
            .iter()
            .all(|tx| txids.insert(tx.compute_txid())),
        "Esplora returned duplicate transactions"
    );
    Ok(block)
}

#[derive(Debug)]
pub struct EsploraClient {
    client: esplora_client::AsyncClient,
    url: SafeUrl,
    cached_chain_id: OnceLock<ChainId>,
}

impl EsploraClient {
    pub fn new(url: &SafeUrl) -> anyhow::Result<Self> {
        info!(
            target: LOG_SERVER,
            %url,
            "Initializing bitcoin esplora backend"
        );
        // URL needs to have any trailing path including '/' removed
        let without_trailing = url.as_str().trim_end_matches('/');

        let builder =
            esplora_client::Builder::new(without_trailing).timeout(ESPLORA_CLIENT_TIMEOUT_SECONDS);
        let client = builder.build_async()?;
        Ok(Self {
            client,
            url: url.clone(),
            cached_chain_id: OnceLock::new(),
        })
    }
}

#[async_trait::async_trait]
impl IServerBitcoinRpc for EsploraClient {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        BitcoinRpcConfig {
            kind: "esplora".to_string(),
            url: self.url.clone(),
        }
    }

    fn get_url(&self) -> SafeUrl {
        self.url.clone()
    }

    async fn get_block_count(&self) -> anyhow::Result<u64> {
        match self.client.get_height().await {
            Ok(height) => Ok(u64::from(height) + 1),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
        Ok(self.client.get_block_hash(u32::try_from(height)?).await?)
    }

    async fn get_block(&self, block_hash: &BlockHash) -> anyhow::Result<bitcoin::Block> {
        let block = self
            .client
            .get_block_by_hash(block_hash)
            .await?
            .context("Block with this hash is not available")?;
        validate_block(block, block_hash)
    }

    async fn get_feerate(&self) -> anyhow::Result<Option<Feerate>> {
        let fee_estimates: HashMap<u16, f64> = self.client.get_fee_estimates().await?;

        let fee_rate_vb = esplora_client::convert_fee_rate(1, fee_estimates).unwrap_or(1.0);

        let fee_rate_kvb = fee_rate_vb * 1_000f32;

        Ok(Some(Feerate {
            sats_per_kvb: (fee_rate_kvb).ceil() as u64,
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) -> anyhow::Result<()> {
        // Preserve server rejections, including already-known transactions.
        // Callers retry broadcasts and must not treat acceptance as confirmation.
        self.client.broadcast(&transaction).await?;
        Ok(())
    }

    async fn get_sync_progress(&self) -> anyhow::Result<Option<f64>> {
        Ok(None)
    }

    async fn get_chain_id(&self) -> anyhow::Result<ChainId> {
        if let Some(chain_id) = self.cached_chain_id.get() {
            return Ok(*chain_id);
        }

        let chain_id = ChainId::new(self.get_block_hash(1).await?);
        let _ = self.cached_chain_id.set(chain_id);
        Ok(chain_id)
    }
}
