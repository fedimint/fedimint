use std::collections::HashMap;

use anyhow::{bail, format_err};
use bitcoin::{BlockHash, Network, ScriptBuf, Transaction, Txid};
use fedimint_core::bitcoin_migration::{
    bitcoin32_to_bitcoin30_block_header, bitcoin32_to_bitcoin30_partial_merkle_tree,
};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::task::TaskHandle;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Feerate};
use tracing::info;

use crate::{DynBitcoindRpc, IBitcoindRpc, IBitcoindRpcFactory, RetryClient};

#[derive(Debug)]
pub struct EsploraFactory;

impl IBitcoindRpcFactory for EsploraFactory {
    fn create_connection(
        &self,
        url: &SafeUrl,
        handle: TaskHandle,
    ) -> anyhow::Result<DynBitcoindRpc> {
        Ok(RetryClient::new(EsploraClient::new(url)?, handle).into())
    }
}

#[derive(Debug)]
pub struct EsploraClient {
    client: esplora_client::AsyncClient,
    url: SafeUrl,
}

impl EsploraClient {
    fn new(url: &SafeUrl) -> anyhow::Result<Self> {
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
impl IBitcoindRpc for EsploraClient {
    async fn get_network(&self) -> anyhow::Result<Network> {
        let genesis_height: u32 = 0;
        let genesis_hash = self.client.get_block_hash(genesis_height).await?;

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

    async fn get_fee_rate(&self, confirmation_target: u16) -> anyhow::Result<Option<Feerate>> {
        let fee_estimates: HashMap<u16, f64> = self.client.get_fee_estimates().await?;

        let fee_rate_vb =
            esplora_client::convert_fee_rate(confirmation_target.into(), fee_estimates)
                .unwrap_or(1.0);

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
            info!(?error, "Error broadcasting transaction");
        });
    }

    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>> {
        Ok(self
            .client
            .get_tx_status(txid)
            .await?
            .block_height
            .map(u64::from))
    }

    async fn is_tx_in_block(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
        block_height: u64,
    ) -> anyhow::Result<bool> {
        let tx_status = self.client.get_tx_status(txid).await?;

        let is_in_block_height = tx_status
            .block_height
            .is_some_and(|height| u64::from(height) == block_height);

        if is_in_block_height {
            let tx_block_hash = tx_status.block_hash.ok_or(anyhow::format_err!(
                "Tx has a block height without a block hash"
            ))?;
            anyhow::ensure!(
                block_hash == &tx_block_hash,
                "Block height for block hash does not match expected height"
            );
        }

        Ok(is_in_block_height)
    }

    async fn watch_script_history(&self, _: &ScriptBuf) -> anyhow::Result<()> {
        // no watching needed, has all the history already
        Ok(())
    }

    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> anyhow::Result<Vec<bitcoin::Transaction>> {
        let transactions = self
            .client
            .scripthash_txs(script, None)
            .await?
            .into_iter()
            .map(|tx| tx.to_tx())
            .collect::<Vec<_>>();

        Ok(transactions)
    }

    async fn get_txout_proof(&self, txid: Txid) -> anyhow::Result<TxOutProof> {
        let proof = self
            .client
            .get_merkle_block(&txid)
            .await?
            .ok_or(format_err!("No merkle proof found"))?;

        Ok(TxOutProof {
            block_header: bitcoin32_to_bitcoin30_block_header(&proof.header),
            merkle_proof: bitcoin32_to_bitcoin30_partial_merkle_tree(&proof.txn),
        })
    }

    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        BitcoinRpcConfig {
            kind: "esplora".to_string(),
            url: self.url.clone(),
        }
    }
}
