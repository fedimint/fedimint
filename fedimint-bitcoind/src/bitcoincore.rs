#[cfg(test)]
mod tests;

use bitcoin::{Address, ScriptBuf, Txid};
use bitcoincore_rpc::json::ImportDescriptors;
use bitcoincore_rpc::{Auth, RpcApi};
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::block_in_place;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_BITCOIND_CORE;
use tracing::{debug, warn};

use crate::{BitcoinRpcError, BlockchainInfo, IBitcoindRpc};

fn ensure_wallet_loaded<E>(
    wallet_name: &str,
    list_loaded_wallets: impl FnOnce() -> Result<Vec<String>, E>,
    list_wallet_dir: impl FnOnce() -> Result<Vec<String>, E>,
    load_wallet: impl FnOnce() -> Result<(), E>,
    create_wallet: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    if list_loaded_wallets()?
        .iter()
        .any(|loaded_wallet| loaded_wallet == wallet_name)
    {
        return Ok(());
    }

    if list_wallet_dir()?
        .iter()
        .any(|wallet| wallet == wallet_name)
    {
        load_wallet()
    } else {
        create_wallet()
    }
}

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
    ) -> Result<Self, BitcoinRpcError> {
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
        let default_client = ::bitcoincore_rpc::Client::new(&default_url_str, auth.clone())
            .map_err(|source| BitcoinRpcError::InvalidUrl {
                url: default_url_str.clone(),
                source: Box::new(source),
            })?;
        Self::load_or_create_watch_only_wallet(&default_client, wallet_name)?;

        let wallet_url_str = format!("{url_str}/wallet/{wallet_name}");
        let client = ::bitcoincore_rpc::Client::new(&wallet_url_str, auth).map_err(|source| {
            BitcoinRpcError::InvalidUrl {
                url: wallet_url_str.clone(),
                source: Box::new(source),
            }
        })?;
        Ok(Self { client, network })
    }

    fn load_or_create_watch_only_wallet(
        client: &::bitcoincore_rpc::Client,
        wallet_name: &str,
    ) -> Result<(), BitcoinRpcError> {
        block_in_place(|| {
            ensure_wallet_loaded(
                wallet_name,
                || client.list_wallets(),
                || client.list_wallet_dir(),
                || client.load_wallet(wallet_name).map(drop),
                || {
                    client
                        .create_wallet(wallet_name, Some(true), Some(true), None, None)
                        .map(drop)
                },
            )
        })
        .map_err(|error| BitcoinRpcError::Backend(Box::new(error)))
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for BitcoindClient {
    async fn get_tx_block_height(&self, txid: &Txid) -> Result<Option<u64>, BitcoinRpcError> {
        let info = block_in_place(|| self.client.get_transaction(txid, Some(true)))
            .map_err(|err| warn!(target: LOG_BITCOIND_CORE, err = %err.fmt_compact(), "Unable to get transaction"));
        let height = match info.ok().and_then(|info| info.info.blockhash) {
            None => None,
            Some(hash) => Some(
                block_in_place(|| self.client.get_block_header_info(&hash))
                    .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?
                    .height,
            ),
        };
        Ok(height.map(|h| h as u64))
    }

    async fn watch_script_history(&self, script: &ScriptBuf) -> Result<(), BitcoinRpcError> {
        let address = Address::from_script(script, self.network)
            .map_err(|err| BitcoinRpcError::NonStandardScript(Box::new(err)))?
            .to_string();
        debug!(target: LOG_BITCOIND_CORE, %address, "Watching script history");

        // First get the checksum for the descriptor
        let descriptor = format!("addr({address})");
        let descriptor_info = block_in_place(|| self.client.get_descriptor_info(&descriptor))
            .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?;
        let checksum =
            descriptor_info
                .checksum
                .ok_or_else(|| BitcoinRpcError::InvalidResponse {
                    message: "Descriptor info carries no checksum".to_string(),
                })?;

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
        })
        .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?;

        // Verify that the import was successful
        if import_results.iter().all(|r| r.success) {
            Ok(())
        } else {
            Err(BitcoinRpcError::InvalidResponse {
                message: format!(
                    "Importing descriptor failed: {:?}",
                    import_results
                        .into_iter()
                        .filter(|r| !r.success)
                        .collect::<Vec<_>>()
                ),
            })
        }
    }

    async fn get_script_history(
        &self,
        script: &ScriptBuf,
    ) -> Result<Vec<bitcoin::Transaction>, BitcoinRpcError> {
        let address = Address::from_script(script, self.network)
            .map_err(|err| BitcoinRpcError::NonStandardScript(Box::new(err)))?
            .to_string();
        let mut results = vec![];
        let list = block_in_place(|| {
            self.client
                .list_transactions(Some(&address), None, None, Some(true))
        })
        .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?;
        for tx in list {
            let tx = block_in_place(|| self.client.get_transaction(&tx.info.txid, Some(true)))
                .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?;
            let raw_tx = tx
                .transaction()
                .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?;
            results.push(raw_tx);
        }
        Ok(results)
    }

    async fn get_txout_proof(&self, txid: Txid) -> Result<TxOutProof, BitcoinRpcError> {
        TxOutProof::consensus_decode_whole(
            &block_in_place(|| self.client.get_tx_out_proof(&[txid], None))
                .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?,
            &ModuleDecoderRegistry::default(),
        )
        .map_err(BitcoinRpcError::Decode)
    }

    async fn get_info(&self) -> Result<BlockchainInfo, BitcoinRpcError> {
        let info = block_in_place(|| self.client.get_blockchain_info())
            .map_err(|err| BitcoinRpcError::Backend(Box::new(err)))?;
        Ok(BlockchainInfo {
            block_height: info.blocks,
            synced: !info.initial_block_download,
        })
    }
}
