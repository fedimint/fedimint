use std::path::PathBuf;

use anyhow::{Context, anyhow, ensure};
use bitcoin::{BlockHash, Network, Transaction};
use bitcoincore_rpc::Error::JsonRpc;
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::jsonrpc::Error::Rpc;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use fedimint_core::Feerate;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::runtime::block_in_place;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_BITCOIND_CORE;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::info;

#[derive(Debug)]
pub struct BitcoindClient {
    client: Client,
    url: SafeUrl,
}

impl BitcoindClient {
    pub fn new(url: &SafeUrl, cookie: Option<PathBuf>) -> anyhow::Result<Self> {
        let auth = match cookie {
            Some(path) => {
                ensure!(
                    url.username().is_empty(),
                    "When a bitcoind cookie file is provided, the Bitcoin Rpc Url auth must be empty."
                );

                Auth::CookieFile(path)
            }
            None => Auth::UserPass(
                url.username().to_owned(),
                url.password()
                    .context("Bitcoin RPC URL is missing password")?
                    .to_owned(),
            ),
        };

        let url = url
            .without_auth()
            .map_err(|()| anyhow!("Failed to strip auth from Bitcoin Rpc Url"))?;

        Ok(Self {
            client: Client::new(url.as_str(), auth)?,
            url,
        })
    }
}

#[async_trait::async_trait]
impl IServerBitcoinRpc for BitcoindClient {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        BitcoinRpcConfig {
            kind: "bitcoind".to_string(),
            url: self.url.clone(),
        }
    }

    fn get_url(&self) -> SafeUrl {
        self.url.clone()
    }

    async fn get_network(&self) -> anyhow::Result<Network> {
        block_in_place(|| self.client.get_blockchain_info())
            .map(|network| network.chain)
            .map_err(anyhow::Error::from)
    }

    async fn get_block_count(&self) -> anyhow::Result<u64> {
        // The RPC function is confusingly named and actually returns the block height
        block_in_place(|| self.client.get_block_count())
            .map(|height| height + 1)
            .map_err(anyhow::Error::from)
    }

    async fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
        block_in_place(|| self.client.get_block_hash(height)).map_err(anyhow::Error::from)
    }

    async fn get_block(&self, hash: &BlockHash) -> anyhow::Result<bitcoin::Block> {
        block_in_place(|| self.client.get_block(hash)).map_err(anyhow::Error::from)
    }

    async fn get_feerate(&self) -> anyhow::Result<Option<Feerate>> {
        let feerate = block_in_place(|| {
            self.client
                .estimate_smart_fee(1, Some(EstimateMode::Conservative))
        })?
        .fee_rate
        .map(|per_kb| Feerate {
            sats_per_kvb: per_kb.to_sat(),
        });

        Ok(feerate)
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        match block_in_place(|| self.client.send_raw_transaction(&transaction)) {
            // Bitcoin core's RPC will return error code -27 if a transaction is already in a block.
            // This is considered a success case, so we don't surface the error log.
            //
            // https://github.com/bitcoin/bitcoin/blob/daa56f7f665183bcce3df146f143be37f33c123e/src/rpc/protocol.h#L48
            Err(JsonRpc(Rpc(e))) if e.code == -27 => (),
            Err(e) => info!(target: LOG_BITCOIND_CORE, ?e, "Error broadcasting transaction"),
            Ok(_) => (),
        }
    }

    async fn get_sync_percentage(&self) -> anyhow::Result<Option<f64>> {
        Ok(Some(
            block_in_place(|| self.client.get_blockchain_info())?.verification_progress,
        ))
    }
}
