use std::collections::HashMap;
use std::fmt;

use ::bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use ::bitcoincore_rpc::jsonrpc::error::RpcError;
use ::bitcoincore_rpc::{jsonrpc, Auth, RpcApi};
use anyhow::{bail, format_err};
use bitcoin_hashes::hex::ToHex;
use electrum_client::ElectrumApi;
use fedimint_core::module::__reexports::serde_json::Value;
use jsonrpc::error::Error as JsonError;
use serde::Deserialize;
use tracing::{instrument, warn};
use url::Url;

use super::*;

// <https://github.com/bitcoin/bitcoin/blob/ec0a4ad67769109910e3685da9c56c1b9f42414e/src/rpc/protocol.h#L48>
const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;

// <https://blockstream.info/api/block-height/0>
const MAINNET_GENESIS_BLOCK_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
// <https://blockstream.info/testnet/api/block-height/0>
const TESTNET_GENESIS_BLOCK_HASH: &str =
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
// <https://mempool.space/signet/api/block-height/0>
const SIGNET_GENESIS_BLOCK_HASH: &str =
    "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";

pub fn from_url_to_url_auth(url: &Url) -> Result<(String, Auth)> {
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

#[derive(Debug)]
pub struct ElectrumFactory;
impl IBitcoindRpcFactory for ElectrumFactory {
    fn create(&self, url: &Url, handle: TaskHandle) -> Result<DynBitcoindRpc> {
        Ok(RetryClient::new(ElectrumClient::new(url)?, handle).into())
    }
}

#[derive(Debug)]
pub struct EsploraFactory;
impl IBitcoindRpcFactory for EsploraFactory {
    fn create(&self, url: &Url, handle: TaskHandle) -> Result<DynBitcoindRpc> {
        Ok(RetryClient::new(EsploraClient::new(url)?, handle).into())
    }
}

#[derive(Debug)]
pub struct BitcoindFactory;
impl IBitcoindRpcFactory for BitcoindFactory {
    fn create(&self, url: &Url, handle: TaskHandle) -> Result<DynBitcoindRpc> {
        let (url, auth) = from_url_to_url_auth(url)?;
        let bitcoind_client =
            ::bitcoincore_rpc::Client::new(&url, auth).map_err(anyhow::Error::from)?;
        let retry_client =
            RetryClient::new(Client(ErrorReporting::new(url, bitcoind_client)), handle);

        Ok(retry_client.into())
    }
}

/// Wrapper around [`bitcoincore_rpc::Client`] logging failures
///
/// In the future we might tweak which errors are worth reporting exactly.
#[derive(Debug)]
struct ErrorReporting<C> {
    // TODO: Url
    addr: String,
    inner: C,
}

impl<C> ErrorReporting<C> {
    fn new(addr: String, inner: C) -> Self
    where
        C: RpcApi,
    {
        Self { addr, inner }
    }
}

impl<C> RpcApi for ErrorReporting<C>
where
    C: RpcApi,
{
    fn call<T: for<'a> Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[Value],
    ) -> ::bitcoincore_rpc::Result<T> {
        self.inner.call(cmd, args).map_err(|e| {
            warn!(
                addr = self.addr,
                "bitcoind returned error on cmd '{}': {}", cmd, e
            );
            e
        })
    }
}

#[derive(Debug)]
struct Client<T>(T);

#[async_trait]
impl<T> IBitcoindRpc for Client<T>
where
    T: ::bitcoincore_rpc::RpcApi + Debug + Send + Sync,
{
    #[instrument(
        skip(self),
        name = "bitcoincore_rpc::get_network",
        level = "DEBUG",
        ret,
        err
    )]
    async fn get_network(&self) -> Result<Network> {
        let network = fedimint_core::task::block_in_place(|| {
            self.0.get_blockchain_info().map_err(anyhow::Error::from)
        })?;
        Ok(match network.chain.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            n => panic!("Unknown Network \"{n}\""),
        })
    }

    #[instrument(
        skip(self),
        name = "bitcoincore_rpc::get_block_height",
        level = "DEBUG",
        ret,
        err
    )]
    async fn get_block_height(&self) -> Result<u64> {
        fedimint_core::task::block_in_place(|| {
            self.0
                .get_block_count()
                .map_err(anyhow::Error::from)
                .map_err(Into::into)
        })
    }

    #[instrument(
        skip(self),
        name = "bitcoincore_rpc::get_block_hash",
        level = "DEBUG",
        ret,
        err
    )]
    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        fedimint_core::task::block_in_place(|| {
            bitcoincore_rpc::RpcApi::get_block_hash(&self.0, height)
                .map_err(anyhow::Error::from)
                .map_err(Into::into)
        })
    }

    #[instrument(
        skip(self),
        name = "bitcoincore_rpc::get_fee_rate",
        level = "DEBUG",
        ret,
        err
    )]
    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
        Ok(fedimint_core::task::block_in_place(|| {
            self.0
                .estimate_smart_fee(confirmation_target, Some(EstimateMode::Conservative))
                .map_err(anyhow::Error::from)
        })?
        .fee_rate
        .map(|per_kb| Feerate {
            sats_per_kvb: per_kb.to_sat(),
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        fedimint_core::task::block_in_place(|| match self.0.send_raw_transaction(&transaction) {
            // for our purposes, this is not an error
            Err(::bitcoincore_rpc::Error::JsonRpc(JsonError::Rpc(RpcError {
                code: RPC_VERIFY_ALREADY_IN_CHAIN,
                ..
            }))) => {}
            Err(error) => {
                info!(?error, "Error broadcasting transaction");
            }
            Ok(_) => {}
        })
    }

    async fn was_transaction_confirmed_in(
        &self,
        transaction: &Transaction,
        height: u64,
    ) -> Result<bool> {
        let block_hash = self.get_block_hash(height).await?;
        let block = fedimint_core::task::block_in_place(|| {
            self.0.get_block(&block_hash).map_err(anyhow::Error::from)
        })?;
        Ok(block
            .txdata
            .iter()
            .any(|tx| tx.txid() == transaction.txid()))
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

#[async_trait]
impl IBitcoindRpc for ElectrumClient {
    async fn get_network(&self) -> Result<Network> {
        let resp = fedimint_core::task::block_in_place(|| {
            self.0.server_features().map_err(anyhow::Error::from)
        })?;
        Ok(match resp.genesis_hash.to_hex().as_str() {
            MAINNET_GENESIS_BLOCK_HASH => Network::Bitcoin,
            TESTNET_GENESIS_BLOCK_HASH => Network::Testnet,
            SIGNET_GENESIS_BLOCK_HASH => Network::Signet,
            hash => {
                warn!("Unknown genesis hash {hash} - assuming regtest");
                Network::Regtest
            }
        })
    }

    async fn get_block_height(&self) -> Result<u64> {
        fedimint_core::task::block_in_place(|| {
            Ok(self.0.block_headers_subscribe_raw()?.height as u64)
        })
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        fedimint_core::task::block_in_place(|| {
            Ok(self
                .0
                .block_headers(height as usize, 1)?
                .headers
                .get(0)
                .ok_or_else(|| format_err!("empty block headers response"))?
                .block_hash())
        })
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
        fedimint_core::task::block_in_place(|| {
            let estimate = self.0.estimate_fee(confirmation_target as usize)?;
            let min_fee = self.0.relay_fee()?;

            // convert fee rate estimate or min fee to sats
            let sats_per_kvb = estimate.max(min_fee) * 100_000_000f64;
            Ok(Some(Feerate {
                sats_per_kvb: sats_per_kvb.ceil() as u64,
            }))
        })
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        fedimint_core::task::block_in_place(|| {
            let mut bytes = vec![];
            bitcoin::consensus::Encodable::consensus_encode(&transaction, &mut bytes)
                .expect("can't fail");
            let _ = self.0.transaction_broadcast_raw(&bytes).map_err(|error| {
                info!(?error, "Error broadcasting transaction");
            });
        });
    }

    async fn was_transaction_confirmed_in(
        &self,
        transaction: &Transaction,
        height: u64,
    ) -> Result<bool> {
        if self.get_block_height().await? <= height {
            bail!("Electrum backend does not contain the block at {height}H yet");
        }

        fedimint_core::task::block_in_place(|| {
            let txid = transaction.txid();

            let output = transaction
                .output
                .first()
                .ok_or(format_err!("Transaction must contain at least one output"))?;

            // if transaction is confirmed, we're going to find the confirmation event in
            // the history of ifs first output
            Ok(self
                .0
                .script_get_history(&output.script_pubkey)?
                .iter()
                .any(|history_item| {
                    (history_item.height as u64) == height && history_item.tx_hash == txid
                }))
        })
    }
}

pub struct EsploraClient(esplora_client::AsyncClient);

impl EsploraClient {
    fn new(url: &Url) -> anyhow::Result<Self> {
        // Url needs to have any trailing path including '/' removed
        let without_trailing = url.as_str().trim_end_matches('/');

        let builder = esplora_client::Builder::new(without_trailing);
        let client = builder.build_async()?;
        Ok(Self(client))
    }
}

impl fmt::Debug for EsploraClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("EsploraClient [url: {}]", self.0.url()))
    }
}

#[async_trait]
impl IBitcoindRpc for EsploraClient {
    async fn get_network(&self) -> Result<Network> {
        let genesis_height: u32 = 0;
        let genesis_hash = self.0.get_block_hash(genesis_height).await?;

        let network = match genesis_hash.to_hex().as_str() {
            MAINNET_GENESIS_BLOCK_HASH => Network::Bitcoin,
            TESTNET_GENESIS_BLOCK_HASH => Network::Testnet,
            SIGNET_GENESIS_BLOCK_HASH => Network::Signet,
            hash => {
                warn!("Unknown genesis hash {hash} - assuming regtest");
                Network::Regtest
            }
        };

        Ok(network)
    }

    async fn get_block_height(&self) -> Result<u64> {
        match self.0.get_height().await {
            Ok(height) => Ok(height as u64),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        self.0
            .get_block_hash(height as u32)
            .await
            .map_err(anyhow::Error::from)
            .map_err(Into::into)
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
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
            info!(?error, "Error broadcasting transaction");
        });
    }

    async fn was_transaction_confirmed_in(
        &self,
        transaction: &Transaction,
        height: u64,
    ) -> Result<bool> {
        let status = self
            .0
            .get_tx_status(&transaction.txid())
            .await
            .map_err(anyhow::Error::from)?;
        Ok(status
            .map(|status| status.block_height == Some(height as u32))
            .unwrap_or(false))
    }
}
