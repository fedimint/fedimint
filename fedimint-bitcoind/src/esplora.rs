use std::collections::HashMap;

use anyhow::format_err;
use bitcoin::{BlockHash, Network, Script, Transaction, Txid};
use bitcoin_hashes::hex::ToHex;
use fedimint_core::task::TaskHandle;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Feerate};
use tracing::{info, warn};

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
pub struct EsploraClient(esplora_client::AsyncClient);

impl EsploraClient {
    fn new(url: &SafeUrl) -> anyhow::Result<Self> {
        // URL needs to have any trailing path including '/' removed
        let without_trailing = url.as_str().trim_end_matches('/');

        let builder = esplora_client::Builder::new(without_trailing);
        let client = builder.build_async()?;
        Ok(Self(client))
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for EsploraClient {
    async fn get_network(&self) -> anyhow::Result<Network> {
        let genesis_height: u32 = 0;
        let genesis_hash = self.0.get_block_hash(genesis_height).await?;

        let network = match genesis_hash.to_hex().as_str() {
            crate::MAINNET_GENESIS_BLOCK_HASH => Network::Bitcoin,
            crate::TESTNET_GENESIS_BLOCK_HASH => Network::Testnet,
            crate::SIGNET_GENESIS_BLOCK_HASH => Network::Signet,
            hash => {
                warn!("Unknown genesis hash {hash} - assuming regtest");
                Network::Regtest
            }
        };

        Ok(network)
    }

    async fn get_block_count(&self) -> anyhow::Result<u64> {
        match self.0.get_height().await {
            Ok(height) => Ok(height as u64 + 1),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
        Ok(self.0.get_block_hash(height as u32).await?)
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> anyhow::Result<Option<Feerate>> {
        let fee_estimates: HashMap<String, f64> = self.0.get_fee_estimates().await?;

        let fee_rate_vb =
            esplora_client::convert_fee_rate(confirmation_target.into(), fee_estimates)?;

        let fee_rate_kvb = fee_rate_vb * 1_000f32;

        Ok(Some(Feerate {
            sats_per_kvb: (fee_rate_kvb).ceil() as u64,
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        let _ = self.0.broadcast(&transaction).await.map_err(|error| {
            // `esplora-client` v0.5.0 only surfaces HTTP error codes, which prevents us
            // from detecting errors for transactions already submitted.
            // TODO: Suppress `esplora-client` already submitted errors when client is
            // updated
            // https://github.com/fedimint/fedimint/issues/3732
            info!(?error, "Error broadcasting transaction");
        });
    }

    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>> {
        Ok(self
            .0
            .get_tx_status(txid)
            .await?
            .block_height
            .map(|height| height as u64))
    }

    async fn watch_script_history(&self, _: &Script) -> anyhow::Result<()> {
        // no watching needed, has all the history already
        Ok(())
    }

    async fn get_script_history(
        &self,
        script: &Script,
    ) -> anyhow::Result<Vec<bitcoin::Transaction>> {
        let transactions = self
            .0
            .scripthash_txs(script, None)
            .await?
            .into_iter()
            .map(|tx| tx.to_tx())
            .collect::<Vec<_>>();

        Ok(transactions)
    }
    async fn get_txout_proof(&self, txid: Txid) -> anyhow::Result<TxOutProof> {
        let proof = self
            .0
            .get_merkle_block(&txid)
            .await?
            .ok_or(format_err!("No merkle proof found"))?;

        Ok(TxOutProof {
            block_header: proof.header,
            merkle_proof: proof.txn,
        })
    }
}
