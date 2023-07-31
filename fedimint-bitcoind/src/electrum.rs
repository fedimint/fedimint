use std::fmt;

use anyhow::anyhow as format_err;
use bitcoin::{BlockHash, Network, Script, Transaction, Txid};
use bitcoin_hashes::hex::ToHex;
use electrum_client::ElectrumApi;
use fedimint_core::task::{block_in_place, TaskHandle};
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::{apply, async_trait_maybe_send, Feerate};
use tracing::{info, warn};
use url::Url;

use crate::{DynBitcoindRpc, IBitcoindRpc, IBitcoindRpcFactory, RetryClient};

#[derive(Debug)]
pub struct ElectrumFactory;

impl IBitcoindRpcFactory for ElectrumFactory {
    fn create_connection(&self, url: &Url, handle: TaskHandle) -> anyhow::Result<DynBitcoindRpc> {
        Ok(RetryClient::new(ElectrumClient::new(url)?, handle).into())
    }
}

pub struct ElectrumClient(electrum_client::Client);

impl ElectrumClient {
    fn new(url: &Url) -> anyhow::Result<Self> {
        Ok(Self(electrum_client::Client::new(url.as_str())?))
    }
}

impl fmt::Debug for ElectrumClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ElectrumClient")
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for ElectrumClient {
    async fn get_network(&self) -> anyhow::Result<Network> {
        let resp = block_in_place(|| self.0.server_features())?;
        Ok(match resp.genesis_hash.to_hex().as_str() {
            crate::MAINNET_GENESIS_BLOCK_HASH => Network::Bitcoin,
            crate::TESTNET_GENESIS_BLOCK_HASH => Network::Testnet,
            crate::SIGNET_GENESIS_BLOCK_HASH => Network::Signet,
            hash => {
                warn!("Unknown genesis hash {hash} - assuming regtest");
                Network::Regtest
            }
        })
    }

    async fn get_block_count(&self) -> anyhow::Result<u64> {
        Ok(block_in_place(|| self.0.block_headers_subscribe_raw())?.height as u64 + 1)
    }

    async fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
        let result = block_in_place(|| self.0.block_headers(height as usize, 1))?;
        Ok(result
            .headers
            .get(0)
            .ok_or_else(|| format_err!("empty block headers response"))?
            .block_hash())
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> anyhow::Result<Option<Feerate>> {
        let estimate = block_in_place(|| self.0.estimate_fee(confirmation_target as usize))?;
        let min_fee = block_in_place(|| self.0.relay_fee())?;

        // convert fee rate estimate or min fee to sats
        let sats_per_kvb = estimate.max(min_fee) * 100_000_000f64;
        Ok(Some(Feerate {
            sats_per_kvb: sats_per_kvb.ceil() as u64,
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        let mut bytes = vec![];
        bitcoin::consensus::Encodable::consensus_encode(&transaction, &mut bytes)
            .expect("can't fail");
        let _ = block_in_place(|| self.0.transaction_broadcast_raw(&bytes)).map_err(|error| {
            info!(?error, "Error broadcasting transaction");
        });
    }

    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>> {
        let tx = block_in_place(|| self.0.transaction_get(txid))
            .map_err(|error| info!(?error, "Unable to get raw transaction"));
        match tx.ok() {
            None => Ok(None),
            Some(tx) => {
                let output = tx
                    .output
                    .first()
                    .ok_or(format_err!("Transaction must contain at least one output"))?;
                let history = block_in_place(|| self.0.script_get_history(&output.script_pubkey))?;
                Ok(history.first().map(|history| history.height as u64))
            }
        }
    }

    async fn watch_script_history(
        &self,
        script: &Script,
    ) -> anyhow::Result<Vec<bitcoin::Transaction>> {
        let mut results = vec![];
        let transactions = block_in_place(|| self.0.script_get_history(script))?;
        for history in transactions.into_iter() {
            results.push(block_in_place(|| self.0.transaction_get(&history.tx_hash))?);
        }
        Ok(results)
    }

    async fn get_txout_proof(&self, _txid: Txid) -> anyhow::Result<TxOutProof> {
        // FIXME: Not sure how to implement for electrum yet, but the client cannot use
        // electrum regardless right now
        unimplemented!()
    }
}
