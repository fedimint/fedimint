use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::{BlockHash, Network, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_core::{ChainId, Feerate};
use fedimint_server_core::bitcoin_rpc::{IServerBitcoinRpc, ServerBitcoinRpcMonitor};

use super::BitcoindClientWithFallback;
use super::backend::Backend;

/// Mutable fake endpoint state used to exercise outages and recovery.
#[derive(Debug)]
struct State {
    chain: ChainId,
    count: u64,
    ibd: bool,
    offline: bool,
    hang: bool,
    fail_reads: bool,
    fail_broadcast: bool,
    calls: Vec<String>,
    transactions: Vec<Transaction>,
    count_started: Option<Arc<tokio::sync::Notify>>,
    count_release: Option<Arc<tokio::sync::Notify>>,
    blocking_identity: Option<Arc<BlockingGate>>,
}

/// A controlled non-abortable transport call, like Core's blocking HTTP RPC.
#[derive(Debug, Default)]
struct BlockingGate {
    released: Mutex<bool>,
    changed: Condvar,
    finished: tokio::sync::Notify,
}

impl BlockingGate {
    fn wait(&self) {
        let (released, _) = self
            .changed
            .wait_timeout_while(
                self.released.lock().unwrap(),
                Duration::from_secs(5),
                |released| !*released,
            )
            .unwrap();
        assert!(*released, "test must release blocking RPC");
        self.finished.notify_one();
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

/// Test RPC with independently controllable health, identity, and responses.
#[derive(Debug)]
struct Fake {
    state: Mutex<State>,
    url: SafeUrl,
}

fn chain(network: Network) -> ChainId {
    // Distinct hashes suffice for these policy tests; no real chain data is used.
    ChainId::new(genesis_block(network).block_hash())
}

impl Fake {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                chain: chain(Network::Bitcoin),
                count: 100,
                ibd: false,
                offline: false,
                hang: false,
                fail_reads: false,
                fail_broadcast: false,
                calls: vec![],
                transactions: vec![],
                count_started: None,
                count_release: None,
                blocking_identity: None,
            }),
            url: format!("http://{name}.invalid").parse().unwrap(),
        })
    }

    fn call(&self, method: &str) -> Result<std::sync::MutexGuard<'_, State>> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(method.to_owned());
        ensure!(!state.offline, "endpoint offline");
        Ok(state)
    }

    fn calls(&self, method: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| *call == method)
            .count()
    }
}

#[async_trait::async_trait]
impl IServerBitcoinRpc for Fake {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        BitcoinRpcConfig {
            kind: "fake".to_owned(),
            url: self.url.clone(),
        }
    }
    fn get_url(&self) -> SafeUrl {
        self.url.clone()
    }
    async fn get_block_count(&self) -> Result<u64> {
        let (count, started, release) = {
            let state = self.call("count")?;
            (
                state.count,
                state.count_started.clone(),
                state.count_release.clone(),
            )
        };
        if let Some(started) = started {
            started.notify_one();
        }
        if let Some(release) = release {
            release.notified().await;
        }
        Ok(count)
    }
    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let (hash, hang, blocking) = {
            let state = self.call(&format!("hash:{height}"))?;
            if height == 1 {
                (
                    state.chain.block_hash(),
                    state.hang,
                    state.blocking_identity.clone(),
                )
            } else {
                ensure!(!state.fail_reads, "hash read failed");
                (genesis_block(Network::Bitcoin).block_hash(), false, None)
            }
        };
        if hang {
            std::future::pending::<()>().await;
        }
        if let Some(blocking) = blocking {
            fedimint_core::runtime::block_in_place(|| blocking.wait());
        }
        Ok(hash)
    }
    async fn get_block(&self, hash: &BlockHash) -> Result<bitcoin::Block> {
        let state = self.call(&format!("block:{hash}"))?;
        ensure!(!state.fail_reads, "block read failed");
        Ok(genesis_block(Network::Bitcoin))
    }
    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        let state = self.call("fee")?;
        ensure!(!state.fail_reads, "fee read failed");
        Ok(Some(Feerate {
            sats_per_kvb: state.count,
        }))
    }
    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        let mut state = self.call("broadcast")?;
        state.transactions.push(transaction);
        ensure!(!state.fail_broadcast, "broadcast rejected");
        Ok(())
    }
    async fn get_sync_progress(&self) -> Result<Option<f64>> {
        Ok(Some(if self.call("progress")?.ibd { 0.5 } else { 1.0 }))
    }
    async fn is_in_initial_block_download(&self) -> Result<bool> {
        Ok(self.call("ibd")?.ibd)
    }
    async fn get_chain_id(&self) -> Result<ChainId> {
        Ok(self.call("chain")?.chain)
    }
}

fn hybrid() -> (BitcoindClientWithFallback, Arc<Fake>, Arc<Fake>) {
    let primary = Fake::new("primary");
    let fallback = Fake::new("fallback");
    let mut primary_backend = Backend::new("bitcoind", primary.clone());
    let mut fallback_backend = Backend::new("esplora", fallback.clone());
    for backend in [&mut primary_backend, &mut fallback_backend] {
        backend.deadline = Duration::from_millis(50);
        backend.success_ttl = Duration::ZERO;
        backend.failure_ttl = Duration::ZERO;
    }
    (
        BitcoindClientWithFallback {
            bitcoind_client: primary_backend,
            esplora_client: fallback_backend,
            chain_id: OnceLock::new(),
        },
        primary,
        fallback,
    )
}

#[tokio::test]
async fn healthy_primary_preserves_arguments_results_and_cached_identity() {
    let (rpc, primary, fallback) = hybrid();
    let block = genesis_block(Network::Bitcoin);
    assert_eq!(rpc.get_block_count().await.unwrap(), 100);
    assert_eq!(rpc.get_block_hash(42).await.unwrap(), block.block_hash());
    assert_eq!(rpc.get_block(&block.block_hash()).await.unwrap(), block);
    assert_eq!(rpc.get_feerate().await.unwrap().unwrap().sats_per_kvb, 100);
    assert_eq!(rpc.get_chain_id().await.unwrap(), chain(Network::Bitcoin));
    assert_eq!(rpc.get_sync_progress().await.unwrap(), None);
    assert_eq!(rpc.get_url(), primary.get_url());
    assert_eq!(rpc.get_bitcoin_rpc_config().url, primary.get_url());
    assert_eq!(primary.calls("hash:42"), 1);
    assert_eq!(fallback.calls("hash:42"), 0);
    assert_eq!(fallback.calls("fee"), 0);
    assert_eq!(primary.calls("hash:1"), 1);
    assert_eq!(fallback.calls("hash:1"), 1);
}

#[tokio::test]
async fn read_errors_use_fallback_and_preserve_both_failures() {
    let (rpc, primary, fallback) = hybrid();
    primary.state.lock().unwrap().fail_reads = true;
    let hash = genesis_block(Network::Bitcoin).block_hash();
    assert_eq!(rpc.get_block_hash(42).await.unwrap(), hash);
    assert_eq!(rpc.get_block(&hash).await.unwrap().block_hash(), hash);
    assert!(rpc.get_feerate().await.unwrap().is_some());
    assert_eq!(fallback.calls("hash:42"), 1);
    assert_eq!(fallback.calls(&format!("block:{hash}")), 1);
    fallback.state.lock().unwrap().fail_reads = true;
    let error = rpc.get_feerate().await.unwrap_err().to_string();
    assert!(error.contains("bitcoind: fee read failed"), "{error}");
    assert!(error.contains("esplora: fee read failed"), "{error}");
}

#[tokio::test]
async fn offline_primary_boots_from_trusted_fallback_then_recovers() {
    let (rpc, primary, fallback) = hybrid();
    // No well-known network pin: arbitrary/custom chains work too.
    fallback.state.lock().unwrap().chain = chain(Network::Signet);
    primary.state.lock().unwrap().offline = true;
    assert_eq!(rpc.get_chain_id().await.unwrap(), chain(Network::Signet));
    assert_eq!(rpc.get_block_count().await.unwrap(), 100);
    {
        let mut state = primary.state.lock().unwrap();
        state.offline = false;
        state.chain = chain(Network::Signet);
    }
    assert!(rpc.get_feerate().await.is_ok());
    assert_eq!(primary.calls("fee"), 1);
}

#[tokio::test]
async fn mismatched_startup_fails_closed_until_corrected() {
    let (rpc, primary, fallback) = hybrid();
    fallback.state.lock().unwrap().chain = chain(Network::Testnet);
    assert!(rpc.get_feerate().await.is_err());
    assert_eq!(primary.calls("fee"), 0);
    assert_eq!(fallback.calls("fee"), 0);
    fallback.state.lock().unwrap().chain = chain(Network::Bitcoin);
    assert!(rpc.get_feerate().await.is_ok());
}

#[tokio::test]
async fn recovered_primary_must_match_remembered_chain() {
    let (rpc, primary, fallback) = hybrid();
    assert!(rpc.get_block_count().await.is_ok());
    primary.state.lock().unwrap().offline = true;
    assert!(rpc.get_block_count().await.is_ok());
    {
        let mut state = primary.state.lock().unwrap();
        state.offline = false;
        state.chain = chain(Network::Testnet);
    }
    assert!(rpc.get_feerate().await.is_ok());
    assert_eq!(primary.calls("fee"), 0);
    assert_eq!(fallback.calls("fee"), 1);
    primary.state.lock().unwrap().chain = chain(Network::Bitcoin);
    assert!(rpc.get_feerate().await.is_ok());
    assert_eq!(primary.calls("fee"), 1);
}

#[tokio::test]
async fn ibd_or_stale_primary_does_not_hide_healthy_fallback() {
    for ibd in [false, true] {
        let (rpc, primary, fallback) = hybrid();
        {
            let mut state = primary.state.lock().unwrap();
            state.ibd = ibd;
            state.count = if ibd { 100 } else { 90 };
        }
        assert_eq!(rpc.get_block_count().await.unwrap(), 100);
        assert_eq!(rpc.get_sync_progress().await.unwrap(), None);
        rpc.get_block_hash(42).await.unwrap();
        assert_eq!(primary.calls("hash:42"), 0);
        assert_eq!(fallback.calls("hash:42"), 1);
        fallback.state.lock().unwrap().fail_reads = true;
        assert!(rpc.get_block_hash(42).await.is_err());
        assert_eq!(primary.calls("hash:42"), 0);
    }
}

#[tokio::test]
async fn ibd_without_fallback_does_not_report_synchronized() {
    let (rpc, primary, fallback) = hybrid();
    primary.state.lock().unwrap().ibd = true;
    fallback.state.lock().unwrap().offline = true;
    assert!(rpc.get_sync_progress().await.is_err());
    assert!(rpc.get_block_count().await.is_err());
}

#[tokio::test]
async fn hung_endpoint_does_not_stall_other_endpoint_or_repeat_probes() {
    for primary_hangs in [false, true] {
        let (mut rpc, primary, fallback) = hybrid();
        let (hung, backend) = if primary_hangs {
            (&primary, &mut rpc.bitcoind_client)
        } else {
            (&fallback, &mut rpc.esplora_client)
        };
        backend.failure_ttl = Duration::from_secs(30);
        hung.state.lock().unwrap().hang = true;
        let call = rpc.get_block_count();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), call)
                .await
                .unwrap()
                .unwrap(),
            100
        );
        assert_eq!(rpc.get_block_count().await.unwrap(), 100);
        assert_eq!(
            hung.calls("hash:1"),
            1,
            "failure cooldown must suppress repeated probes"
        );
    }
}

#[tokio::test]
async fn health_snapshot_avoids_probing_every_wallet_read() {
    let (mut rpc, primary, fallback) = hybrid();
    rpc.bitcoind_client.success_ttl = Duration::from_secs(5);
    rpc.esplora_client.success_ttl = Duration::from_secs(5);
    rpc.get_block_hash(42).await.unwrap();
    rpc.get_block_hash(43).await.unwrap();
    assert_eq!(primary.calls("ibd"), 1);
    assert_eq!(primary.calls("count"), 1);
    assert_eq!(fallback.calls("count"), 1);
}

#[tokio::test]
async fn late_health_refresh_cannot_undo_an_observed_failure() {
    let fake = Fake::new("primary");
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    {
        let mut state = fake.state.lock().unwrap();
        state.count_started = Some(started.clone());
        state.count_release = Some(release.clone());
    }
    let backend = Backend::new("bitcoind", fake.clone());
    let refreshing = backend.clone();
    let task =
        fedimint_core::runtime::spawn(
            "test-delayed-health",
            async move { refreshing.status().await },
        );
    started.notified().await;
    backend.failed(&anyhow::anyhow!("newer request failed"));
    release.notify_one();
    assert!(task.await.unwrap().is_err());
    assert!(
        backend
            .status()
            .await
            .unwrap_err()
            .to_string()
            .contains("newer request failed")
    );
    assert_eq!(fake.calls("count"), 1);
}

#[test]
fn production_health_timing_matches_operator_contract() {
    let backend = Backend::new("bitcoind", Fake::new("primary"));
    assert_eq!(backend.deadline, Duration::from_secs(5));
    assert_eq!(backend.success_ttl, Duration::from_secs(5));
    assert_eq!(backend.failure_ttl, Duration::from_secs(30));
}

#[tokio::test(start_paused = true)]
async fn successful_health_expiry_rechecks_readiness_without_repeating_identity() {
    let (mut rpc, primary, fallback) = hybrid();
    rpc.bitcoind_client.success_ttl = Duration::from_secs(5);
    rpc.esplora_client.success_ttl = Duration::from_secs(5);
    rpc.get_block_hash(42).await.unwrap();
    primary.state.lock().unwrap().ibd = true;
    tokio::time::advance(Duration::from_secs(4)).await;
    rpc.get_block_hash(43).await.unwrap();
    assert_eq!(primary.calls("hash:43"), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    rpc.get_block_hash(44).await.unwrap();
    assert_eq!(primary.calls("hash:44"), 0);
    assert_eq!(fallback.calls("hash:44"), 1);
    assert_eq!(primary.calls("ibd"), 2);
    assert_eq!(primary.calls("hash:1"), 1);
}

#[tokio::test(start_paused = true)]
async fn failed_health_expiry_rechecks_recovered_identity_before_use() {
    let (mut rpc, primary, fallback) = hybrid();
    rpc.bitcoind_client.failure_ttl = Duration::from_secs(30);
    primary.state.lock().unwrap().offline = true;
    rpc.get_block_hash(42).await.unwrap();
    {
        let mut state = primary.state.lock().unwrap();
        state.offline = false;
        state.chain = chain(Network::Testnet);
    }
    tokio::time::advance(Duration::from_secs(29)).await;
    rpc.get_block_hash(43).await.unwrap();
    assert_eq!(primary.calls("hash:1"), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    rpc.get_block_hash(44).await.unwrap();
    assert_eq!(primary.calls("hash:1"), 2);
    assert_eq!(
        primary.calls("hash:44"),
        0,
        "wrong recovered chain must remain quarantined"
    );
    assert_eq!(fallback.calls("hash:44"), 1);
    primary.state.lock().unwrap().chain = chain(Network::Bitcoin);
    tokio::time::advance(Duration::from_secs(30)).await;
    rpc.get_block_hash(45).await.unwrap();
    assert_eq!(primary.calls("hash:45"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timed_out_blocking_probe_holds_slot_until_transport_exits() {
    let fake = Fake::new("primary");
    let gate = Arc::new(BlockingGate::default());
    fake.state.lock().unwrap().blocking_identity = Some(gate.clone());
    let mut backend = Backend::new("bitcoind", fake.clone());
    backend.deadline = Duration::from_millis(100);
    backend.success_ttl = Duration::ZERO;
    backend.failure_ttl = Duration::from_millis(50);
    assert!(backend.status().await.is_err());
    assert_eq!(fake.calls("hash:1"), 1);
    fedimint_core::runtime::sleep(Duration::from_millis(60)).await;
    assert!(backend.status().await.is_err());
    assert_eq!(
        fake.calls("hash:1"),
        1,
        "must not spawn a second blocking RPC"
    );
    gate.release();
    gate.finished.notified().await;
    fake.state.lock().unwrap().blocking_identity = None;
    fedimint_core::runtime::sleep(Duration::from_millis(60)).await;
    assert!(backend.status().await.is_ok());
    assert_eq!(fake.calls("hash:1"), 2);
}

async fn wait_for_status(monitor: &ServerBitcoinRpcMonitor, present: bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while monitor.status().is_some() != present {
            fedimint_core::runtime::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("monitor should publish new health");
}

#[tokio::test]
async fn monitor_allows_known_chain_broadcast_with_ibd_primary_and_offline_fallback() {
    let (rpc, primary, fallback) = hybrid();
    let tasks = TaskGroup::new();
    let monitor = ServerBitcoinRpcMonitor::new(rpc.into_dyn(), Duration::from_millis(1), &tasks);
    wait_for_status(&monitor, true).await;
    primary.state.lock().unwrap().ibd = true;
    fallback.state.lock().unwrap().offline = true;
    wait_for_status(&monitor, false).await;
    monitor
        .submit_transaction(genesis_block(Network::Bitcoin).txdata.remove(0))
        .await
        .unwrap();
    assert_eq!(primary.calls("broadcast"), 1);
    assert_eq!(fallback.calls("broadcast"), 0);
    tasks
        .shutdown_join_all(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn monitor_cold_broadcast_requires_identity_but_not_read_readiness() {
    let (rpc, primary, fallback) = hybrid();
    primary.state.lock().unwrap().offline = true;
    fallback.state.lock().unwrap().offline = true;
    let tasks = TaskGroup::new();
    let monitor = ServerBitcoinRpcMonitor::new(rpc.into_dyn(), Duration::from_secs(60), &tasks);
    let tx = genesis_block(Network::Bitcoin).txdata.remove(0);
    assert!(monitor.submit_transaction(tx.clone()).await.is_err());
    assert_eq!(primary.calls("broadcast"), 0);
    assert_eq!(fallback.calls("broadcast"), 0);
    {
        let mut state = primary.state.lock().unwrap();
        state.offline = false;
        state.ibd = true;
    }
    assert!(monitor.status().is_none());
    monitor.submit_transaction(tx).await.unwrap();
    assert_eq!(primary.calls("broadcast"), 1);
    tasks
        .shutdown_join_all(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn accepted_primary_broadcast_does_not_send_transaction_to_fallback() {
    let (rpc, primary, fallback) = hybrid();
    let tx = genesis_block(Network::Bitcoin).txdata.remove(0);
    rpc.submit_transaction(tx.clone()).await.unwrap();
    assert_eq!(primary.state.lock().unwrap().transactions, vec![tx]);
    assert_eq!(fallback.calls("broadcast"), 0);
}

#[tokio::test]
async fn rejected_primary_broadcast_uses_fallback_and_retains_both_failures() {
    let (rpc, primary, fallback) = hybrid();
    primary.state.lock().unwrap().fail_broadcast = true;
    let tx = genesis_block(Network::Bitcoin).txdata.remove(0);
    rpc.submit_transaction(tx.clone()).await.unwrap();
    assert_eq!(
        fallback.state.lock().unwrap().transactions,
        vec![tx.clone()]
    );
    fallback.state.lock().unwrap().fail_broadcast = true;
    let error = rpc.submit_transaction(tx).await.unwrap_err().to_string();
    assert!(error.contains("bitcoind: broadcast rejected"), "{error}");
    assert!(error.contains("esplora: broadcast rejected"), "{error}");
}

#[tokio::test]
async fn broadcast_does_not_use_wrong_chain_after_recovery() {
    let (rpc, primary, fallback) = hybrid();
    primary.state.lock().unwrap().offline = true;
    rpc.get_block_count().await.unwrap();
    {
        let mut state = primary.state.lock().unwrap();
        state.offline = false;
        state.chain = chain(Network::Testnet);
    }
    rpc.submit_transaction(genesis_block(Network::Bitcoin).txdata.remove(0))
        .await
        .unwrap();
    assert_eq!(primary.calls("broadcast"), 0);
    assert_eq!(fallback.calls("broadcast"), 1);
}
