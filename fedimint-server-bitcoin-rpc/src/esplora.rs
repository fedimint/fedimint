use std::collections::HashMap;

use anyhow::{Context, bail};
use bitcoin::{BlockHash, Network, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Feerate, apply, async_trait_maybe_send};
use fedimint_logging::LOG_BITCOIND_ESPLORA;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::info;

#[derive(Debug)]
pub struct EsploraClient {
    client: esplora_client::AsyncClient,
    url: SafeUrl,
}

impl EsploraClient {
    pub fn new(url: &SafeUrl) -> anyhow::Result<Self> {
        // URL needs to have any trailing path including '/' removed
        let without_trailing = url.as_str().trim_end_matches('/');

        let builder = esplora_client::Builder::new(without_trailing);
        let client = builder.build_async()?;
        Ok(Self {
            client,
            url: url.clone(),
        })
    }
}

#[apply(async_trait_maybe_send!)]
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

    async fn get_network(&self) -> anyhow::Result<Network> {
        let genesis_hash = self.client.get_block_hash(0).await?;

        let network = match genesis_hash.to_string().as_str() {
            crate::MAINNET_GENESIS_BLOCK_HASH => Network::Bitcoin,
            crate::TESTNET_GENESIS_BLOCK_HASH => Network::Testnet,
            crate::SIGNET_GENESIS_BLOCK_HASH => Network::Signet,
            crate::REGTEST_GENESIS_BLOCK_HASH => Network::Regtest,
            hash => {
                bail!("Unknown genesis hash {hash}");
            }
        };

        Ok(network)
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
        let _ = self.client.broadcast(&transaction).await.map_err(|error| {
            // `esplora-client` v0.6.0 only surfaces HTTP error codes, which prevents us
            // from detecting errors for transactions already submitted.
            // TODO: Suppress `esplora-client` already submitted errors when client is
            // updated
            // https://github.com/fedimint/fedimint/issues/3732
            info!(target: LOG_BITCOIND_ESPLORA, ?error, "Error broadcasting transaction");
        });
    }

    async fn get_sync_percentage(&self) -> anyhow::Result<Option<f64>> {
        Ok(None)
    }
}
