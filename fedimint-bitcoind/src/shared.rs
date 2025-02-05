use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_core::Feerate;
use fedimint_logging::LOG_BITCOIN;
use fedimint_server_core::ServerModuleShared;
use tokio::sync::{watch, Mutex};
use tracing::debug;

/// Used for estimating a feerate that will confirm within a target number of
/// blocks.
///
/// Since the wallet's UTXOs are a shared resource, we need to reduce the risk
/// of a peg-out transaction getting stuck in the mempool, hence we use a low
/// confirmation target. Other fee bumping techniques, such as RBF and CPFP, can
/// help mitigate this problem but are out-of-scope for this version of the
/// wallet.
pub const CONFIRMATION_TARGET: u16 = 1;

use crate::DynBitcoindRpc;
type SharedKey = (bitcoin::Network, SafeUrl);

/// A (potentially) shared (between server modules) bitcoin utility trait
///
/// Multiple Fedimint modules might want same Bitcoin-network facilities
/// like monitoring the feerate or block count, and each of them doing the same
/// thing does not scale very well.
///
/// This type allows deduplicating the work, by sharing it via
/// `ServerModuleInitArgs::shared`.
///
/// In theory different modules might be configured to use different Bitcoin
/// network/bitcoin sources, so shared facilities here are keyed over the the
/// Bitcoin rpc url to use.
struct ServerModuleSharedBitcoinInner {
    task_group: TaskGroup,
    feerate_rx: tokio::sync::Mutex<BTreeMap<SharedKey, watch::Receiver<Option<Feerate>>>>,
    block_count_rx: tokio::sync::Mutex<BTreeMap<SharedKey, watch::Receiver<Option<u64>>>>,
}

impl ServerModuleSharedBitcoinInner {
    pub async fn feerate_receiver(
        &self,
        network: bitcoin::Network,
        btc_rpc: DynBitcoindRpc,
    ) -> anyhow::Result<watch::Receiver<Option<Feerate>>> {
        let key = (network, btc_rpc.get_bitcoin_rpc_config().url);
        let mut write = self.feerate_rx.lock().await;

        if let Some(v) = write.get(&key) {
            return Ok(v.clone());
        }

        let (tx, rx) = watch::channel(None);

        btc_rpc
            .clone()
            .spawn_fee_rate_update_task(&self.task_group, network, 1, {
                move |feerate| {
                    debug!(target: LOG_BITCOIN, %feerate, "New feerate");
                    let _ = tx.send(Some(feerate));
                }
            })?;

        write.insert(key, rx.clone());

        Ok(rx)
    }
    pub async fn block_count_receiver(
        &self,
        network: bitcoin::Network,
        btc_rpc: DynBitcoindRpc,
    ) -> watch::Receiver<Option<u64>> {
        let key = (network, btc_rpc.get_bitcoin_rpc_config().url);
        let mut write = self.block_count_rx.lock().await;

        if let Some(v) = write.get(&key) {
            return v.clone();
        }

        let (tx, rx) = watch::channel(None);

        btc_rpc
            .clone()
            .spawn_block_count_update_task(&self.task_group, {
                move |block_count| {
                    debug!(target: LOG_BITCOIN, %block_count, "New block count");
                    let _ = tx.send(Some(block_count));
                }
            });

        write.insert(key, rx.clone());

        rx
    }
}

#[derive(Clone)]
pub struct ServerModuleSharedBitcoin {
    inner: Arc<ServerModuleSharedBitcoinInner>,
}

impl ServerModuleSharedBitcoin {
    pub async fn feerate_receiver(
        &self,
        network: bitcoin::Network,
        btc_rpc: DynBitcoindRpc,
    ) -> anyhow::Result<watch::Receiver<Option<Feerate>>> {
        self.inner.feerate_receiver(network, btc_rpc).await
    }
    pub async fn block_count_receiver(
        &self,
        network: bitcoin::Network,
        btc_rpc: DynBitcoindRpc,
    ) -> watch::Receiver<Option<u64>> {
        self.inner.block_count_receiver(network, btc_rpc).await
    }
}
impl ServerModuleShared for ServerModuleSharedBitcoin {
    fn new(task_group: TaskGroup) -> Self {
        Self {
            inner: Arc::new(ServerModuleSharedBitcoinInner {
                task_group,
                feerate_rx: Mutex::default(),
                block_count_rx: Mutex::default(),
            }),
        }
    }
}
