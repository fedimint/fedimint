#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]

use std::env;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Result, format_err};
use bitcoin::{ScriptBuf, Transaction, Txid};
use bitcoincore_rpc::{Auth, RpcApi};
use esplora_client::{AsyncClient, Builder};
use fedimint_core::encoding::Decodable;
use fedimint_core::envs::FM_FORCE_BITCOIN_RPC_URL_ENV;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::block_in_place;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_BITCOIND_CORE;
use tracing::info;

pub fn create_esplora_rpc(url: &SafeUrl) -> Result<DynBitcoindRpc> {
    let url = env::var(FM_FORCE_BITCOIN_RPC_URL_ENV)
        .ok()
        .map(|s| SafeUrl::parse(&s))
        .transpose()?
        .unwrap_or_else(|| url.clone());

    Ok(EsploraClient::new(&url)?.into_dyn())
}

pub type DynBitcoindRpc = Arc<dyn IBitcoindRpc + Send + Sync>;

/// Trait that allows interacting with the Bitcoin blockchain
///
/// Functions may panic if the bitcoind node is not reachable.
#[apply(async_trait_maybe_send!)]
pub trait IBitcoindRpc: Debug + Send + Sync + 'static {
    /// If a transaction is included in a block, returns the block height.
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>>;

    /// Get script transaction history
    async fn get_script_history(&self, script: &ScriptBuf) -> Result<Vec<Transaction>>;

    /// Returns a proof that a tx is included in the bitcoin blockchain
    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof>;

    fn into_dyn(self) -> DynBitcoindRpc
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}

#[derive(Debug)]
pub struct BitcoindClient {
    client: ::bitcoincore_rpc::Client,
}

impl BitcoindClient {
    pub fn new(url: SafeUrl, username: String, password: String) -> anyhow::Result<Self> {
        let auth = Auth::UserPass(username, password);
        let url_str = if let Some(port) = url.port() {
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
        };
        Ok(Self {
            client: ::bitcoincore_rpc::Client::new(&url_str, auth)?,
        })
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for BitcoindClient {
    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>> {
        let info = block_in_place(|| self.client.get_raw_transaction_info(txid, None)).map_err(
            |error| info!(target: LOG_BITCOIND_CORE, ?error, "Unable to get raw transaction"),
        );
        let height = match info.ok().and_then(|info| info.blockhash) {
            None => None,
            Some(hash) => Some(block_in_place(|| self.client.get_block_header_info(&hash))?.height),
        };
        Ok(height.map(|h| h as u64))
    }

    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> anyhow::Result<Vec<bitcoin::Transaction>> {
        let mut results = vec![];
        let list = block_in_place(|| {
            self.client
                .list_transactions(Some(&script.to_string()), None, None, Some(true))
        })?;
        for tx in list {
            let raw_tx = block_in_place(|| self.client.get_raw_transaction(&tx.info.txid, None))?;
            results.push(raw_tx);
        }
        Ok(results)
    }

    async fn get_txout_proof(&self, txid: Txid) -> anyhow::Result<TxOutProof> {
        TxOutProof::consensus_decode_whole(
            &block_in_place(|| self.client.get_tx_out_proof(&[txid], None))?,
            &ModuleDecoderRegistry::default(),
        )
        .map_err(|error| format_err!("Could not decode tx: {}", error))
    }
}

#[derive(Debug)]
pub struct EsploraClient {
    client: AsyncClient,
}

impl EsploraClient {
    pub fn new(url: &SafeUrl) -> anyhow::Result<Self> {
        Ok(Self {
            // URL needs to have any trailing path including '/' removed
            client: Builder::new(url.as_str().trim_end_matches('/')).build_async()?,
        })
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for EsploraClient {
    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>> {
        Ok(self
            .client
            .get_tx_status(txid)
            .await?
            .block_height
            .map(u64::from))
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
            block_header: proof.header,
            merkle_proof: proof.txn,
        })
    }
}
