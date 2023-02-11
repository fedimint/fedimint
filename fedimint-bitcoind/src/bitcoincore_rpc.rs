use std::fmt;

use ::bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use ::bitcoincore_rpc::jsonrpc::error::RpcError;
use ::bitcoincore_rpc::{jsonrpc, Auth, RpcApi};
use anyhow::{bail, format_err, Context};
use bitcoin::consensus::Encodable;
use bitcoin_hashes::hex::ToHex;
use electrum_client::ElectrumApi;
use fedimint_api::bitcoin_rpc::BitcoindRpcBackend;
use fedimint_api::module::__reexports::serde_json::Value;
use jsonrpc::error::Error as JsonError;
use serde::Deserialize;
use tracing::warn;
use url::Url;

use super::*;

// <https://github.com/bitcoin/bitcoin/blob/ec0a4ad67769109910e3685da9c56c1b9f42414e/src/rpc/protocol.h#L48>
const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;

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

pub fn make_bitcoin_rpc_backend(
    backend: &BitcoindRpcBackend,
    task_handle: TaskHandle,
) -> Result<DynBitcoindRpc> {
    match backend {
        BitcoindRpcBackend::Bitcoind(url) => make_bitcoind_rpc(url, task_handle)
            .context("bitcoind rpc backend initialization failed"),
        BitcoindRpcBackend::Electrum(url) => make_electrum_rpc(url, task_handle)
            .context("electrum rpc backend initialization failed"),
    }
}

pub fn make_bitcoind_rpc(url: &Url, task_handle: TaskHandle) -> Result<DynBitcoindRpc> {
    let (url, auth) = from_url_to_url_auth(url)?;
    let bitcoind_client =
        ::bitcoincore_rpc::Client::new(&url, auth).map_err(anyhow::Error::from)?;
    let retry_client = RetryClient::new(
        Client(ErrorReporting::new(url, bitcoind_client)),
        task_handle,
    );

    Ok(retry_client.into())
}

pub fn make_electrum_rpc(url: &Url, _task_handle: TaskHandle) -> Result<DynBitcoindRpc> {
    Ok(ElectrumClient::new(url)?.into())
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
    async fn get_network(&self) -> Result<Network> {
        let network = fedimint_api::task::block_in_place(|| {
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

    async fn get_block_height(&self) -> Result<u64> {
        fedimint_api::task::block_in_place(|| {
            self.0
                .get_block_count()
                .map_err(anyhow::Error::from)
                .map_err(Into::into)
        })
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        fedimint_api::task::block_in_place(|| {
            bitcoincore_rpc::RpcApi::get_block_hash(&self.0, height)
                .map_err(anyhow::Error::from)
                .map_err(Into::into)
        })
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        fedimint_api::task::block_in_place(|| {
            bitcoincore_rpc::RpcApi::get_block(&self.0, hash)
                .map_err(anyhow::Error::from)
                .map_err(Into::into)
        })
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
        Ok(fedimint_api::task::block_in_place(|| {
            self.0
                .estimate_smart_fee(confirmation_target, Some(EstimateMode::Conservative))
                .map_err(anyhow::Error::from)
        })
        .expect("Bitcoind returned an error") // TODO: implement retry logic in case bitcoind is temporarily unreachable
        .fee_rate
        .map(|per_kb| Feerate {
            sats_per_kvb: per_kb.to_sat(),
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        fedimint_api::task::block_in_place(|| match self.0.send_raw_transaction(&transaction) {
            // for our purposes, this is not an error
            Err(::bitcoincore_rpc::Error::JsonRpc(JsonError::Rpc(RpcError {
                code: RPC_VERIFY_ALREADY_IN_CHAIN,
                ..
            }))) => Ok(()),
            Err(e) => Err(anyhow::Error::from(e)),
            Ok(_) => Ok(()),
        })
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
    fn backend_type(&self) -> BitcoinRpcBackendType {
        BitcoinRpcBackendType::Electrum
    }

    async fn get_network(&self) -> Result<Network> {
        let resp = fedimint_api::task::block_in_place(|| {
            self.0.server_features().map_err(anyhow::Error::from)
        })?;
        Ok(match resp.genesis_hash.to_hex().as_str() {
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" => Network::Bitcoin,
            // https://blockstream.info/testnet/block/000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" => Network::Testnet,
            // https://explorer.bc-2.jp/block/00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6" => Network::Signet,
            hash => {
                warn!("Unknown genesis hash {hash} - assuming regtest");
                Network::Regtest
            }
        })
    }

    async fn get_block_height(&self) -> Result<u64> {
        fedimint_api::task::block_in_place(|| {
            Ok(self.0.block_headers_subscribe_raw()?.height as u64)
        })
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        fedimint_api::task::block_in_place(|| {
            Ok(self
                .0
                .block_headers(height as usize, 1)?
                .headers
                .get(0)
                .ok_or_else(|| format_err!("empty block headers response"))?
                .block_hash())
        })
    }

    async fn get_block(&self, _hash: &BlockHash) -> Result<Block> {
        bail!("get_block call not supported on electrum rpc backend")
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
        fedimint_api::task::block_in_place(|| {
            Ok(Some(Feerate {
                sats_per_kvb: (self.0.estimate_fee(confirmation_target as usize)? * 100_000_000f64)
                    .ceil() as u64,
            }))
        })
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        fedimint_api::task::block_in_place(|| {
            let mut bytes = vec![];
            transaction
                .consensus_encode(&mut bytes)
                .expect("can't fail");
            let _txid = self.0.transaction_broadcast_raw(&bytes)?;
            Ok(())
        })
    }

    async fn was_transaction_confirmed_in(
        &self,
        transaction: &Transaction,
        height: u64,
    ) -> Result<bool> {
        if self.get_block_height().await? <= height {
            bail!("Electrum backend does not contain the block at {height}H yet");
        }

        fedimint_api::task::block_in_place(|| {
            let txid = transaction.txid();

            let output = transaction
                .output
                .first()
                .expect("Transaction must contain at least one output");

            // if transaction is confirmed, we're going to find the confirmation event in the history of ifs first output
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
