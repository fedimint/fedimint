use anyhow::{Context, anyhow, ensure};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{BlockHash, Transaction};
use bitcoincore_rpc::Error::JsonRpc;
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::jsonrpc::Error::Rpc;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::runtime::block_in_place;
use fedimint_core::util::SafeUrl;
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::LOG_SERVER;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::info;

#[derive(Debug)]
pub struct BitcoindClient {
    client: Client,
    url: SafeUrl,
}

impl BitcoindClient {
    pub fn new(username: String, password: String, url: &SafeUrl) -> anyhow::Result<Self> {
        let auth = Auth::UserPass(username, password);

        let url = url
            .without_auth()
            .map_err(|()| anyhow!("Failed to strip auth from Bitcoin Rpc Url"))?;

        info!(
            target: LOG_SERVER,
            %url,
            "Initializing bitcoin bitcoind backend"
        );
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

    async fn submit_transaction(&self, transaction: Transaction) -> anyhow::Result<()> {
        match block_in_place(|| self.client.send_raw_transaction(&transaction)) {
            // Bitcoin core's RPC will return error code -27 if a transaction is already in a block.
            // This is considered a success case, so we don't surface it as an error.
            //
            // https://github.com/bitcoin/bitcoin/blob/daa56f7f665183bcce3df146f143be37f33c123e/src/rpc/protocol.h#L48
            Err(JsonRpc(Rpc(e))) if e.code == -27 => Ok(()),
            Err(e) => Err(e.into()),
            Ok(_) => Ok(()),
        }
    }

    async fn submit_package(&self, transactions: &[Transaction]) -> anyhow::Result<()> {
        let raw_txs = serde_json::Value::Array(
            transactions
                .iter()
                .map(|tx| serde_json::Value::String(serialize_hex(tx)))
                .collect(),
        );

        // `bitcoincore-rpc` 0.19 has no typed `submitpackage`, so we issue the
        // call directly. The response is an object whose `package_msg` is
        // "success" only when every transaction was accepted into, or was
        // already in, the mempool.
        //
        // Note there is no counterpart to the error code -27 that
        // `submit_transaction` treats as success: `submitpackage` reports an
        // already-mined transaction as a per-transaction entry in `tx-results`,
        // not as an RPC error, and that entry is deliberately surfaced as a
        // failure. See `IServerBitcoinRpc::submit_package`.
        let response = block_in_place(|| {
            self.client
                .call::<serde_json::Value>("submitpackage", &[raw_txs])
        })?;

        let package_msg = response
            .get("package_msg")
            .and_then(serde_json::Value::as_str)
            .context("submitpackage response is missing package_msg")?;

        ensure!(
            package_msg == "success",
            "Package was rejected: {package_msg} ({response})"
        );

        Ok(())
    }

    async fn get_sync_progress(&self) -> anyhow::Result<Option<f64>> {
        Ok(Some(
            block_in_place(|| self.client.get_blockchain_info())?.verification_progress,
        ))
    }

    async fn get_chain_id(&self) -> anyhow::Result<ChainId> {
        self.get_block_hash(1).await.map(ChainId::new)
    }
}
