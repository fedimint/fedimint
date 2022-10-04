use crate::bitcoind::IBitcoindRpc;
use crate::bitcoind::Result;
use crate::{bitcoind::BitcoindRpc, Feerate};
use async_trait::async_trait;
use bitcoin::{Block, BlockHash, Network, Transaction};
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use bitcoincore_rpc::jsonrpc::error::RpcError;
use bitcoincore_rpc::{jsonrpc, Auth, Error};
use fedimint_api::config::BitcoindRpcCfg;
use fedimint_api::module::__reexports::serde_json::Value;
use jsonrpc::error::Error as JsonError;
use serde::Deserialize;
use std::future::Future;
use std::time::Duration;
use tracing::info;
use tracing::warn;

// <https://github.com/bitcoin/bitcoin/blob/ec0a4ad67769109910e3685da9c56c1b9f42414e/src/rpc/protocol.h#L48>
const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;

pub fn make_bitcoind_rpc(
    cfg: &BitcoindRpcCfg,
) -> std::result::Result<BitcoindRpc, bitcoincore_rpc::Error> {
    let bitcoind_client = bitcoincore_rpc::Client::new(
        &cfg.btc_rpc_address,
        Auth::UserPass(cfg.btc_rpc_user.clone(), cfg.btc_rpc_pass.clone()),
    )?;
    let retry_client = RetryClient {
        inner: ErrorReporting::new(bitcoind_client),
        max_retries: 10,
        base_sleep: Duration::from_millis(10),
    };

    Ok(retry_client.into())
}

/// Wrapper around [`bitcoincore_rpc::Client`] logging failures
///
/// In the future we might tweak which errors are worth reporting exactly.
#[derive(Debug)]
struct ErrorReporting<C> {
    inner: C,
}

impl<C> ErrorReporting<C> {
    fn new(inner: C) -> Self
    where
        C: bitcoincore_rpc::RpcApi,
    {
        Self { inner }
    }
}

impl<C> bitcoincore_rpc::RpcApi for ErrorReporting<C>
where
    C: bitcoincore_rpc::RpcApi,
{
    fn call<T: for<'a> Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[Value],
    ) -> bitcoincore_rpc::Result<T> {
        self.inner.call(cmd, args).map_err(|e| {
            warn!("bitcoind returned error on cmd '{}': {}", cmd, e);
            e
        })
    }
}

/// Wrapper around [`IBitcoindRpc`] that will retry failed calls
#[derive(Debug)]
struct RetryClient<C> {
    inner: C,
    max_retries: u16,
    base_sleep: Duration,
}

impl<C> RetryClient<C> {
    async fn retry_call<T, F, R>(&self, call_fn: F) -> Result<T>
    where
        F: Fn() -> R,
        R: Future<Output = Result<T>>,
    {
        let mut retries = 0;
        let mut fail_sleep = self.base_sleep;
        let ret = loop {
            match call_fn().await {
                Ok(ret) => {
                    break ret;
                }
                Err(e) => {
                    retries += 1;

                    if retries > self.max_retries {
                        return Err(e);
                    }

                    info!("Will retry rpc after {}ms", fail_sleep.as_millis());
                    std::thread::sleep(fail_sleep);
                    fail_sleep *= 2;
                }
            }
        };
        Ok(ret)
    }
}

#[async_trait]
impl<C> IBitcoindRpc for RetryClient<C>
where
    C: IBitcoindRpc,
{
    async fn get_network(&self) -> Result<Network> {
        self.retry_call(|| async { self.inner.get_network().await })
            .await
    }

    async fn get_block_height(&self) -> Result<u64> {
        self.retry_call(|| async { self.inner.get_block_height().await })
            .await
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        self.retry_call(|| async { self.inner.get_block_hash(height).await })
            .await
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        self.retry_call(|| async { self.inner.get_block(hash).await })
            .await
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
        self.retry_call(|| async { self.inner.get_fee_rate(confirmation_target).await })
            .await
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        self.retry_call(|| async { self.inner.submit_transaction(transaction.clone()).await })
            .await
    }
}

#[async_trait]
impl<T> IBitcoindRpc for T
where
    T: bitcoincore_rpc::RpcApi + Send + Sync,
{
    async fn get_network(&self) -> Result<Network> {
        let network = fedimint_api::task::block_in_place(|| {
            self.get_blockchain_info().map_err(anyhow::Error::from)
        })?;
        Ok(match network.chain.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            n => panic!("Unknown Network \"{}\"", n),
        })
    }

    async fn get_block_height(&self) -> Result<u64> {
        fedimint_api::task::block_in_place(|| {
            self.get_block_count()
                .map_err(anyhow::Error::from)
                .map_err(Into::into)
        })
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        fedimint_api::task::block_in_place(|| {
            bitcoincore_rpc::RpcApi::get_block_hash(self, height)
                .map_err(anyhow::Error::from)
                .map_err(Into::into)
        })
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        fedimint_api::task::block_in_place(|| {
            bitcoincore_rpc::RpcApi::get_block(self, hash)
                .map_err(anyhow::Error::from)
                .map_err(Into::into)
        })
    }

    async fn get_fee_rate(&self, confirmation_target: u16) -> Result<Option<Feerate>> {
        Ok(fedimint_api::task::block_in_place(|| {
            self.estimate_smart_fee(confirmation_target, Some(EstimateMode::Conservative))
                .map_err(anyhow::Error::from)
        })
        .expect("Bitcoind returned an error") // TODO: implement retry logic in case bitcoind is temporarily unreachable
        .fee_rate
        .map(|per_kb| Feerate {
            sats_per_kvb: per_kb.as_sat(),
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        fedimint_api::task::block_in_place(|| match self.send_raw_transaction(&transaction) {
            // for our purposes, this is not an error
            Err(Error::JsonRpc(JsonError::Rpc(RpcError {
                code: RPC_VERIFY_ALREADY_IN_CHAIN,
                ..
            }))) => Ok(()),
            Err(e) => Err(anyhow::Error::from(e).into()),
            Ok(_) => Ok(()),
        })
    }
}
