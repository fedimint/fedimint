use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::Context;
use bitcoin::{BlockHash, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::{LOG_BITCOIND_ESPLORA, LOG_SERVER};
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::info;

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

        let builder = esplora_client::Builder::new(without_trailing);
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
        self.client
            .get_block_by_hash(block_hash)
            .await?
            .context("Block with this hash is not available")
    }

    async fn get_feerate(&self) -> anyhow::Result<Option<Feerate>> {
        let fee_estimates: HashMap<u16, f64> = self.client.get_fee_estimates().await?;

        let fee_rate_vb = esplora_client::convert_fee_rate(1, fee_estimates).unwrap_or(1.0);

        let fee_rate_kvb = fee_rate_vb * 1_000f32;

        Ok(Some(Feerate {
            sats_per_kvb: (fee_rate_kvb).ceil() as u64,
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        let _ = self.client.broadcast(&transaction).await.map_err(|err| {
            // `esplora-client` v0.6.0 only surfaces HTTP error codes, which prevents us
            // from detecting errors for transactions already submitted.
            // TODO: Suppress `esplora-client` already submitted errors when client is
            // updated
            // https://github.com/fedimint/fedimint/issues/3732
            info!(target: LOG_BITCOIND_ESPLORA, err = %err.fmt_compact(), "Error broadcasting transaction");
        });
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
