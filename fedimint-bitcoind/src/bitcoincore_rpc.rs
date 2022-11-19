use ::bitcoincore_rpc::bitcoincore_rpc_json::EstimateMode;
use ::bitcoincore_rpc::jsonrpc::error::RpcError;
use ::bitcoincore_rpc::{jsonrpc, Auth, RpcApi};
use fedimint_api::config::BitcoindRpcCfg;
use fedimint_api::module::__reexports::serde_json::Value;
use jsonrpc::error::Error as JsonError;
use serde::Deserialize;
use tracing::warn;

use super::*;

// <https://github.com/bitcoin/bitcoin/blob/ec0a4ad67769109910e3685da9c56c1b9f42414e/src/rpc/protocol.h#L48>
const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;

pub fn make_bitcoind_rpc(cfg: &BitcoindRpcCfg, task_handle: TaskHandle) -> Result<BitcoindRpc> {
    let bitcoind_client = ::bitcoincore_rpc::Client::new(
        &cfg.btc_rpc_address,
        Auth::UserPass(cfg.btc_rpc_user.clone(), cfg.btc_rpc_pass.clone()),
    )
    .map_err(anyhow::Error::from)?;
    let retry_client = RetryClient::new(Client(ErrorReporting::new(bitcoind_client)), task_handle);

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
        C: RpcApi,
    {
        Self { inner }
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
            warn!("bitcoind returned error on cmd '{}': {}", cmd, e);
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
            n => panic!("Unknown Network \"{}\"", n),
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
            Err(e) => Err(anyhow::Error::from(e).into()),
            Ok(_) => Ok(()),
        })
    }
}
