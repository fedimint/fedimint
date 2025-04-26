use std::fmt::Debug;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{ScriptBuf, Transaction, Txid};
use esplora_client::{AsyncClient, Builder};
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send};

pub fn create_esplora_rpc(url: &SafeUrl) -> anyhow::Result<DynEsploradRpc> {
    Ok(EsploraClient::new(url)?.into_dyn())
}

pub type DynEsploradRpc = Arc<dyn IEsploraRpc>;

/// Trait that allows interacting with the Bitcoin blockchain
///
/// Functions may panic if the bitcoind node is not reachable.
#[apply(async_trait_maybe_send!)]
pub trait IEsploraRpc: Debug + Send + Sync + 'static {
    /// If a transaction is included in a block, returns the block height.
    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>>;

    /// Get script transaction history
    async fn get_script_history(&self, script: &ScriptBuf) -> anyhow::Result<Vec<Transaction>>;

    /// Returns a proof that a tx is included in the bitcoin blockchain
    async fn get_txout_proof(&self, txid: Txid) -> anyhow::Result<TxOutProof>;

    fn into_dyn(self) -> DynEsploradRpc
    where
        Self: Sized,
    {
        Arc::new(self)
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
impl IEsploraRpc for EsploraClient {
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
            .context("No merkle proof found")?;

        Ok(TxOutProof {
            block_header: proof.header,
            merkle_proof: proof.txn,
        })
    }
}
