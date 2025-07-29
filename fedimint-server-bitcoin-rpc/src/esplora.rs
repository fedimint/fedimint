use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::{Context, bail};
use bitcoin::{BlockHash, Network, Transaction};
use fedimint_core::Feerate;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_logging::{LOG_BITCOIND_ESPLORA, LOG_SERVER};
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::{debug, info};

// <https://blockstream.info/api/block-height/0>
const MAINNET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

// <https://blockstream.info/testnet/api/block-height/0>
const TESTNET: &str = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";

// <https://mempool.space/signet/api/block-height/0>
const SIGNET: &str = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";

// See <https://bitcoin.stackexchange.com/questions/122778/is-the-regtest-genesis-hash-always-the-same-or-not>
// <https://github.com/bitcoin/bitcoin/blob/d82283950f5ff3b2116e705f931c6e89e5fdd0be/src/kernel/chainparams.cpp#L478>
const REGTEST: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

#[derive(Debug)]
pub struct EsploraClient {
    client: esplora_client::AsyncClient,
    url: SafeUrl,
    cached_network: OnceLock<Network>,
}

impl EsploraClient {
    pub fn new(url: &SafeUrl) -> anyhow::Result<Self> {
        info!(
            target: LOG_SERVER,
            %url,
            "Initiallizing bitcoin esplora backend"
        );
        // URL needs to have any trailing path including '/' removed
        let without_trailing = url.as_str().trim_end_matches('/');

        let builder = esplora_client::Builder::new(without_trailing);
        let client = builder.build_async()?;
        Ok(Self {
            client,
            url: url.clone(),
            cached_network: OnceLock::new(),
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

    async fn get_network(&self) -> anyhow::Result<Network> {
        // Return cached network if already fetched
        if let Some(network) = self.cached_network.get() {
            return Ok(*network);
        }

        // Fetch and cache the network
        let genesis_hash = self.client.get_block_hash(0).await.inspect_err(|err| {
            debug!(
                target: LOG_BITCOIND_ESPLORA,
                err = %err.fmt_compact(),
                "Error getting network (genesis hash) from esplora backend");
        })?;

        let network = match genesis_hash.to_string().as_str() {
            MAINNET => Network::Bitcoin,
            TESTNET => Network::Testnet,
            SIGNET => Network::Signet,
            REGTEST => Network::Regtest,
            hash => {
                bail!("Unknown genesis hash {hash}");
            }
        };

        // Cache the successful result
        let _ = self.cached_network.set(network);
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

    async fn get_sync_progress(&self) -> anyhow::Result<Option<f64>> {
        Ok(None)
    }
}
