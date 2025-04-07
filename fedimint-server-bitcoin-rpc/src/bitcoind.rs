use std::env;
use std::path::PathBuf;

use anyhow::{anyhow as format_err, bail};
use bitcoin::{BlockHash, Network, Transaction};
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::{Auth, RpcApi};
use fedimint_core::Feerate;
use fedimint_core::envs::{BitcoinRpcConfig, FM_BITCOIND_COOKIE_FILE_ENV};
use fedimint_core::runtime::block_in_place;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_BITCOIND_CORE;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::info;

#[derive(Debug)]
pub struct BitcoindClient {
    client: ::bitcoincore_rpc::Client,
    url: SafeUrl,
}

impl BitcoindClient {
    pub fn new(url: &SafeUrl) -> anyhow::Result<Self> {
        let safe_url = url.clone();
        let (url, auth) = Self::from_url_to_url_auth(url)?;
        Ok(Self {
            client: ::bitcoincore_rpc::Client::new(&url, auth)?,
            url: safe_url,
        })
    }

    fn from_url_to_url_auth(url: &SafeUrl) -> anyhow::Result<(String, Auth)> {
        Ok((
            (if let Some(port) = url.port() {
                format!(
                    "{}://{}:{port}",
                    url.scheme(),
                    url.host_str().unwrap_or("127.0.0.1")
                )
            } else {
                format!(
                    "{}://{}",
                    url.scheme(),
                    url.host_str().unwrap_or("127.0.0.1")
                )
            }),
            match (
                !url.username().is_empty(),
                env::var(FM_BITCOIND_COOKIE_FILE_ENV),
            ) {
                (true, Ok(_)) => {
                    bail!(
                        "When {FM_BITCOIND_COOKIE_FILE_ENV} is set, the url auth part must be empty."
                    )
                }
                (true, Err(_)) => Auth::UserPass(
                    url.username().to_owned(),
                    url.password()
                        .ok_or_else(|| format_err!("Password missing for {}", url.username()))?
                        .to_owned(),
                ),
                (false, Ok(path)) => Auth::CookieFile(PathBuf::from(path)),
                (false, Err(_)) => Auth::None,
            },
        ))
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
        use bitcoincore_rpc::Error::JsonRpc;
        use bitcoincore_rpc::jsonrpc::Error::Rpc;
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
