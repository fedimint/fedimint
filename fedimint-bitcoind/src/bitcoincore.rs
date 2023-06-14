use anyhow::anyhow as format_err;
use bitcoin::{BlockHash, Network, Transaction, Txid};
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::{Auth, RpcApi};
use fedimint_core::task::{block_in_place, TaskHandle};
use fedimint_core::{apply, async_trait_maybe_send, Feerate};
use tracing::info;
use url::Url;

use crate::{DynBitcoindRpc, IBitcoindRpc, IBitcoindRpcFactory, RetryClient};

#[derive(Debug)]
pub struct BitcoindFactory;

impl IBitcoindRpcFactory for BitcoindFactory {
    fn create_connection(&self, url: &Url, handle: TaskHandle) -> anyhow::Result<DynBitcoindRpc> {
        Ok(RetryClient::new(BitcoinClient::new(url)?, handle).into())
    }
}

#[derive(Debug)]
struct BitcoinClient(::bitcoincore_rpc::Client);

impl BitcoinClient {
    fn new(url: &Url) -> anyhow::Result<Self> {
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

    async fn get_block_height(&self) -> anyhow::Result<u64> {
        block_in_place(|| self.0.get_block_count()).map_err(anyhow::Error::from)
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
}

// TODO: Make private
pub fn from_url_to_url_auth(url: &Url) -> anyhow::Result<(String, Auth)> {
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
        if url.username().is_empty() {
            Auth::None
        } else {
            Auth::UserPass(
                url.username().to_owned(),
                url.password()
                    .ok_or_else(|| format_err!("Password missing for {}", url.username()))?
                    .to_owned(),
            )
        },
    ))
}
