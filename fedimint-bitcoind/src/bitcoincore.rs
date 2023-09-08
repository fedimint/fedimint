use std::env;
use std::io::Cursor;
use std::path::PathBuf;

use anyhow::{anyhow as format_err, bail};
use bitcoin::{BlockHash, Network, Script, Transaction, Txid};
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::{Auth, RpcApi};
use fedimint_core::bitcoinrpc::FM_BITCOIND_COOKIE_FILE_VAR_NAME;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{block_in_place, TaskHandle};
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Feerate};
use tracing::info;

use crate::{DynBitcoindRpc, IBitcoindRpc, IBitcoindRpcFactory, RetryClient};

#[derive(Debug)]
pub struct BitcoindFactory;

impl IBitcoindRpcFactory for BitcoindFactory {
    fn create_connection(
        &self,
        url: &SafeUrl,
        handle: TaskHandle,
    ) -> anyhow::Result<DynBitcoindRpc> {
        Ok(RetryClient::new(BitcoinClient::new(url)?, handle).into())
    }
}

#[derive(Debug)]
struct BitcoinClient(::bitcoincore_rpc::Client);

impl BitcoinClient {
    fn new(url: &SafeUrl) -> anyhow::Result<Self> {
        let (url, auth) = from_url_to_url_auth(url)?;
        Ok(Self(::bitcoincore_rpc::Client::new(&url, auth)?))
    }
}

#[apply(async_trait_maybe_send!)]
impl IBitcoindRpc for BitcoinClient {
    async fn get_network(&self) -> anyhow::Result<Network> {
        let network = block_in_place(|| self.0.get_blockchain_info())?;
        Ok(match network.chain.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            n => panic!("Unknown Network \"{n}\""),
        })
    }

    async fn get_block_count(&self) -> anyhow::Result<u64> {
        // The RPC function is confusingly named and actually returns the block height
        block_in_place(|| self.0.get_block_count())
            .map(|height| height + 1)
            .map_err(anyhow::Error::from)
    }

    async fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
        block_in_place(|| self.0.get_block_hash(height)).map_err(anyhow::Error::from)
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> anyhow::Result<Option<Feerate>> {
        let fee = block_in_place(|| {
            self.0
                .estimate_smart_fee(confirmation_target, Some(EstimateMode::Conservative))
        });
        Ok(fee?.fee_rate.map(|per_kb| Feerate {
            sats_per_kvb: per_kb.to_sat(),
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        let send = block_in_place(|| self.0.send_raw_transaction(&transaction));
        let _ = send.map_err(|error| info!(?error, "Error broadcasting transaction"));
    }

    async fn get_tx_block_height(&self, txid: &Txid) -> anyhow::Result<Option<u64>> {
        let info = block_in_place(|| self.0.get_raw_transaction_info(txid, None))
            .map_err(|error| info!(?error, "Unable to get raw transaction"));
        let height = match info.ok().and_then(|info| info.blockhash) {
            None => None,
            Some(hash) => Some(block_in_place(|| self.0.get_block_header_info(&hash))?.height),
        };
        Ok(height.map(|h| h as u64))
    }

    async fn watch_script_history(&self, script: &Script) -> anyhow::Result<Vec<Transaction>> {
        // start watching for this script in our wallet to avoid the need to rescan the
        // blockchain, labeling it so we can reference it later
        block_in_place(|| {
            self.0
                .import_address_script(script, Some(&script.to_string()), Some(false), None)
        })?;

        let mut results = vec![];
        let list = block_in_place(|| {
            self.0
                .list_transactions(Some(&script.to_string()), None, None, Some(true))
        })?;
        for tx in list {
            let raw_tx = block_in_place(|| self.0.get_raw_transaction(&tx.info.txid, None))?;
            results.push(raw_tx);
        }
        Ok(results)
    }

    async fn get_txout_proof(&self, txid: Txid) -> anyhow::Result<TxOutProof> {
        TxOutProof::consensus_decode(
            &mut Cursor::new(block_in_place(|| self.0.get_tx_out_proof(&[txid], None))?),
            &ModuleDecoderRegistry::default(),
        )
        .map_err(|error| format_err!("Could not decode tx: {}", error))
    }
}

// TODO: Make private
pub fn from_url_to_url_auth(url: &SafeUrl) -> anyhow::Result<(String, Auth)> {
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
            env::var(FM_BITCOIND_COOKIE_FILE_VAR_NAME),
        ) {
            (true, Ok(_)) => bail!(
                "When {FM_BITCOIND_COOKIE_FILE_VAR_NAME} is set, the url auth part must be empty."
            ),
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
