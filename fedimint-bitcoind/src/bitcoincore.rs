use bitcoin::{ScriptBuf, Txid};
use bitcoincore_rpc::{Auth, RpcApi};
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::block_in_place;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_BITCOIND_CORE;
use tracing::info;

use crate::{IBitcoindRpc, format_err};

#[derive(Debug)]
pub struct BitcoindClient {
    client: ::bitcoincore_rpc::Client,
}

impl BitcoindClient {
    pub fn new(url: &SafeUrl, username: String, password: String) -> anyhow::Result<Self> {
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
