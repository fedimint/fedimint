use bitcoin::{Address, ScriptBuf, Txid};
use bitcoincore_rpc::json::ImportDescriptors;
use bitcoincore_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoincore_rpc::{Auth, Error as RpcError, RpcApi};
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::block_in_place;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_BITCOIND_CORE;
use tracing::{debug, warn};

use crate::{IBitcoindRpc, format_err};

#[derive(Debug)]
pub struct BitcoindClient {
    client: ::bitcoincore_rpc::Client,
    network: bitcoin::Network,
}

impl BitcoindClient {
    pub fn new(
        url: &SafeUrl,
        username: String,
        password: String,
        wallet_name: &str,
        network: bitcoin::Network,
    ) -> anyhow::Result<Self> {
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

        let default_url_str = format!("{url_str}/wallet/");
        let default_client = ::bitcoincore_rpc::Client::new(&default_url_str, auth.clone())?;
        Self::create_watch_only_wallet(&default_client, wallet_name)?;

        let wallet_url_str = format!("{url_str}/wallet/{wallet_name}");
        let client = ::bitcoincore_rpc::Client::new(&wallet_url_str, auth)?;
        Ok(Self { client, network })
    }

    fn create_watch_only_wallet(
        client: &::bitcoincore_rpc::Client,
        wallet_name: &str,
    ) -> anyhow::Result<()> {
        let create_wallet = block_in_place(|| {
            client.create_wallet(wallet_name, Some(true), Some(true), None, None)
        });

        match create_wallet {
            Ok(_) => Ok(()),
            Err(RpcError::JsonRpc(JsonRpcError::Rpc(rpc_err))) if rpc_err.code == -4 => {
                // Wallet already exists → treat as success
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for BitcoindClient {
    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>> {
        let info = block_in_place(|| self.client.get_transaction(txid, Some(true)))
            .map_err(|err| warn!(target: LOG_BITCOIND_CORE, err = %err.fmt_compact(), "Unable to get transaction"));
        let height = match info.ok().and_then(|info| info.info.blockhash) {
            None => None,
            Some(hash) => Some(block_in_place(|| self.client.get_block_header_info(&hash))?.height),
        };
        Ok(height.map(|h| h as u64))
    }

    async fn watch_script_history(&self, script: &ScriptBuf) -> anyhow::Result<()> {
        let address = Address::from_script(script, self.network)?.to_string();
        debug!(target: LOG_BITCOIND_CORE, %address, "Watching script history");

        // First get the checksum for the descriptor
        let descriptor = format!("addr({address})");
        let descriptor_info = block_in_place(|| self.client.get_descriptor_info(&descriptor))?;
        let checksum = descriptor_info
            .checksum
            .ok_or(anyhow::anyhow!("No checksum"))?;

        // Import the descriptor
        let import_results = block_in_place(|| {
            self.client.import_descriptors(ImportDescriptors {
                descriptor: format!("{descriptor}#{checksum}"),
                timestamp: bitcoincore_rpc::json::Timestamp::Now,
                active: Some(false),
                range: None,
                next_index: None,
                internal: None,
                label: Some(address.clone()),
            })
        })?;

        // Verify that the import was successful
        if import_results.iter().all(|r| r.success) {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Importing descriptor failed: {:?}",
                import_results
                    .into_iter()
                    .filter(|r| !r.success)
                    .collect::<Vec<_>>()
            ))
        }
    }

    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> anyhow::Result<Vec<bitcoin::Transaction>> {
        let address = Address::from_script(script, self.network)?.to_string();
        let mut results = vec![];
        let list = block_in_place(|| {
            self.client
                .list_transactions(Some(&address), None, None, Some(true))
        })?;
        for tx in list {
            let tx = block_in_place(|| self.client.get_transaction(&tx.info.txid, Some(true)))?;
            let raw_tx = tx.transaction()?;
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

    async fn get_info(&self) -> anyhow::Result<(u64, bool)> {
        let info = block_in_place(|| self.client.get_blockchain_info())
            .map_err(|err| anyhow::anyhow!("Unable to get blockchain info {err}"))?;
        Ok((info.blocks, !info.initial_block_download))
    }
}
