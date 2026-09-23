use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::{BlockHash, Network, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_core::{ChainId, Feerate};
use fedimint_server_core::bitcoin_rpc::{IServerBitcoinRpc, ServerBitcoinRpcMonitor};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::BitcoindClientWithFallback;
use crate::esplora::EsploraClient;

/// Mutable fake endpoint state used to exercise outages and recovery.
#[derive(Debug)]
struct State {
    chain: ChainId,
    count: u64,
    ibd: bool,
    offline: bool,
    fail_count: bool,
    fail_reads: bool,
    missing_feerate: bool,
    fail_broadcast: bool,
    calls: Vec<String>,
    transactions: Vec<Transaction>,
}

/// Test RPC with independently controllable identity and responses.
#[derive(Debug)]
struct Fake {
    state: Mutex<State>,
    url: SafeUrl,
}

fn chain(network: Network) -> ChainId {
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
                fail_count: false,
                fail_reads: false,
                missing_feerate: false,
                fail_broadcast: false,
                calls: vec![],
                transactions: vec![],
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
        let state = self.call("count")?;
        ensure!(!state.fail_count, "count failed");
        Ok(state.count)
    }

    async fn get_block_count_and_initial_block_download(&self) -> Result<(u64, bool)> {
        let state = self.call("status")?;
        ensure!(!state.fail_count, "status failed");
        Ok((state.count, state.ibd))
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let state = self.call(&format!("hash:{height}"))?;
        if height == 1 {
            Ok(state.chain.block_hash())
        } else {
            ensure!(!state.fail_reads, "hash read failed");
            Ok(genesis_block(Network::Bitcoin).block_hash())
        }
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<bitcoin::Block> {
        let state = self.call(&format!("block:{hash}"))?;
        ensure!(!state.fail_reads, "block read failed");
        Ok(genesis_block(Network::Bitcoin))
    }

    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        let state = self.call("fee")?;
        ensure!(
            !state.fail_reads,
            "{} fee read failed",
            self.url.host_str().unwrap()
        );
        if state.missing_feerate {
            return Ok(None);
        }
        Ok(Some(Feerate {
            sats_per_kvb: state.count,
        }))
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        let mut state = self.call("broadcast")?;
        state.transactions.push(transaction);
        ensure!(
            !state.fail_broadcast,
            "{} broadcast rejected",
            self.url.host_str().unwrap()
        );
        Ok(())
    }

    async fn get_sync_progress(&self) -> Result<Option<f64>> {
        Ok(Some(if self.call("progress")?.ibd { 0.5 } else { 1.0 }))
    }

    async fn get_chain_id(&self) -> Result<ChainId> {
        Ok(self.call("chain")?.chain)
    }
}

async fn hybrid() -> (BitcoindClientWithFallback, Arc<Fake>, Arc<Fake>) {
    let primary = Fake::new("primary");
    let fallback = Fake::new("fallback");
    let rpc = BitcoindClientWithFallback::from_clients(primary.clone(), fallback.clone())
        .await
        .unwrap();
    (rpc, primary, fallback)
}

#[tokio::test]
async fn healthy_primary_preserves_arguments_results_and_identity() {
    let (rpc, primary, fallback) = hybrid().await;
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
    assert_eq!(primary.calls("chain"), 1);
    assert_eq!(fallback.calls("chain"), 1);
}

#[tokio::test]
async fn local_node_one_block_behind_remains_preferred() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().count = 99;
    fallback.state.lock().unwrap().count = 100;
    assert_eq!(rpc.get_block_count().await.unwrap(), 99);
    assert_eq!(rpc.get_feerate().await.unwrap().unwrap().sats_per_kvb, 99);
    assert_eq!(fallback.calls("count"), 0);
    assert_eq!(fallback.calls("fee"), 0);
}

#[tokio::test]
async fn missing_local_fee_estimate_falls_back_to_esplora() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().missing_feerate = true;
    fallback.state.lock().unwrap().count = 123;

    assert_eq!(rpc.get_feerate().await.unwrap().unwrap().sats_per_kvb, 123);
    assert_eq!(primary.calls("fee"), 1);
    assert_eq!(fallback.calls("fee"), 1);
}

#[tokio::test]
async fn missing_local_fee_estimate_uses_existing_esplora_floor_for_empty_response() {
    let primary = Fake::new("primary");
    primary.state.lock().unwrap().missing_feerate = true;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url: SafeUrl = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let chain_id = chain(Network::Bitcoin).block_hash();
    let server = fedimint_core::runtime::spawn("esplora-test-http", async move {
        for (path, body) in [
            ("/block-height/1", chain_id.to_string()),
            ("/fee-estimates", "{}".to_owned()),
        ] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0; 4096];
                let len = socket.read(&mut chunk).await.unwrap();
                assert_ne!(len, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..len]);
            }
            assert!(
                String::from_utf8_lossy(&request).starts_with(&format!("GET {path} ")),
                "unexpected request: {}",
                String::from_utf8_lossy(&request)
            );
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });

    let fallback = EsploraClient::new(&url).unwrap().into_dyn();
    let rpc = BitcoindClientWithFallback::from_clients(primary.clone(), fallback)
        .await
        .unwrap();

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), rpc.get_feerate())
            .await
            .unwrap()
            .unwrap(),
        Some(Feerate { sats_per_kvb: 1000 })
    );
    assert_eq!(primary.calls("fee"), 1);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn failed_local_fee_request_falls_back_to_esplora() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().fail_reads = true;
    fallback.state.lock().unwrap().count = 123;

    assert_eq!(rpc.get_feerate().await.unwrap().unwrap().sats_per_kvb, 123);
    assert_eq!(primary.calls("fee"), 1);
    assert_eq!(fallback.calls("fee"), 1);
}

#[tokio::test]
async fn failed_local_fee_request_accepts_an_absent_esplora_estimate() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().fail_reads = true;
    fallback.state.lock().unwrap().missing_feerate = true;

    assert_eq!(rpc.get_feerate().await.unwrap(), None);
    assert_eq!(primary.calls("fee"), 1);
    assert_eq!(fallback.calls("fee"), 1);
}

#[tokio::test]
async fn absent_fee_estimate_is_preserved_when_esplora_cannot_supply_one() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().missing_feerate = true;
    fallback.state.lock().unwrap().missing_feerate = true;

    assert_eq!(rpc.get_feerate().await.unwrap(), None);

    fallback.state.lock().unwrap().fail_reads = true;
    assert_eq!(rpc.get_feerate().await.unwrap(), None);
    assert_eq!(primary.calls("fee"), 2);
    assert_eq!(fallback.calls("fee"), 2);
}

#[tokio::test]
async fn missing_local_payload_falls_back_only_for_that_request() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().fail_reads = true;
    let hash = genesis_block(Network::Bitcoin).block_hash();
    assert_eq!(rpc.get_block(&hash).await.unwrap().block_hash(), hash);
    primary.state.lock().unwrap().fail_reads = false;
    assert!(rpc.get_feerate().await.unwrap().is_some());
    assert_eq!(fallback.calls(&format!("block:{hash}")), 1);
    assert_eq!(fallback.calls("fee"), 0);
    assert_eq!(primary.calls("chain"), 1);
}

#[tokio::test]
async fn ibd_uses_fallback_until_first_completed_report_then_latches() {
    let (rpc, primary, fallback) = hybrid().await;
    {
        let mut state = primary.state.lock().unwrap();
        state.ibd = true;
        state.missing_feerate = true;
    }
    fallback.state.lock().unwrap().count = 123;
    assert_eq!(rpc.get_block_count().await.unwrap(), 123);
    assert_eq!(rpc.get_feerate().await.unwrap().unwrap().sats_per_kvb, 123);
    assert_eq!(primary.calls("status"), 1);
    assert_eq!(fallback.calls("count"), 1);
    assert_eq!(fallback.calls("fee"), 1);

    {
        let mut state = primary.state.lock().unwrap();
        state.ibd = false;
        state.count = 99;
    }
    assert_eq!(rpc.get_block_count().await.unwrap(), 99);
    assert_eq!(rpc.get_block_count().await.unwrap(), 99);
    assert_eq!(primary.calls("status"), 2);
    assert_eq!(primary.calls("count"), 1);
    assert_eq!(fallback.calls("count"), 1);
}

#[tokio::test]
async fn offline_primary_boots_from_trusted_fallback_then_recovers() {
    let primary = Fake::new("primary");
    let fallback = Fake::new("fallback");
    fallback.state.lock().unwrap().chain = chain(Network::Signet);
    primary.state.lock().unwrap().offline = true;
    let rpc = BitcoindClientWithFallback::from_clients(primary.clone(), fallback.clone())
        .await
        .unwrap();
    assert_eq!(rpc.get_chain_id().await.unwrap(), chain(Network::Signet));
    assert_eq!(rpc.get_block_count().await.unwrap(), 100);
    {
        let mut state = primary.state.lock().unwrap();
        state.offline = false;
        state.chain = chain(Network::Testnet);
        state.count = 99;
    }
    assert_eq!(rpc.get_block_count().await.unwrap(), 99);
    assert_eq!(primary.calls("chain"), 1);
    assert_eq!(fallback.calls("chain"), 1);
}

#[tokio::test]
async fn mismatched_startup_is_rejected() {
    let primary = Fake::new("primary");
    let fallback = Fake::new("fallback");
    fallback.state.lock().unwrap().chain = chain(Network::Testnet);
    assert!(
        BitcoindClientWithFallback::from_clients(primary.clone(), fallback.clone())
            .await
            .is_err()
    );
    assert_eq!(primary.calls("fee"), 0);
    assert_eq!(fallback.calls("fee"), 0);
}

#[tokio::test]
async fn unavailable_startup_comparison_does_not_prevent_later_identity_read() {
    let primary = Fake::new("primary");
    let fallback = Fake::new("fallback");
    primary.state.lock().unwrap().offline = true;
    fallback.state.lock().unwrap().offline = true;
    let rpc = BitcoindClientWithFallback::from_clients(primary.clone(), fallback.clone())
        .await
        .unwrap();
    assert!(rpc.get_chain_id().await.is_err());

    primary.state.lock().unwrap().offline = false;
    fallback.state.lock().unwrap().offline = false;
    assert_eq!(rpc.get_chain_id().await.unwrap(), chain(Network::Bitcoin));
    assert_eq!(rpc.get_chain_id().await.unwrap(), chain(Network::Bitcoin));
    assert_eq!(primary.calls("chain"), 3);
    assert_eq!(fallback.calls("chain"), 2);
}

#[tokio::test]
async fn startup_chain_check_is_not_repeated() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().chain = chain(Network::Testnet);
    assert!(rpc.get_feerate().await.is_ok());
    assert_eq!(rpc.get_chain_id().await.unwrap(), chain(Network::Bitcoin));
    assert_eq!(primary.calls("chain"), 1);
    assert_eq!(fallback.calls("chain"), 1);
    assert_eq!(primary.calls("fee"), 1);
}

#[tokio::test]
async fn accepted_primary_broadcast_does_not_send_to_fallback() {
    let (rpc, primary, fallback) = hybrid().await;
    let tx = genesis_block(Network::Bitcoin).txdata.remove(0);
    rpc.submit_transaction(tx.clone()).await.unwrap();
    assert_eq!(primary.state.lock().unwrap().transactions, vec![tx]);
    assert_eq!(fallback.calls("broadcast"), 0);
}

#[tokio::test]
async fn policy_rejection_falls_back() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().fail_broadcast = true;
    let tx = genesis_block(Network::Bitcoin).txdata.remove(0);
    rpc.submit_transaction(tx.clone()).await.unwrap();
    assert_eq!(fallback.state.lock().unwrap().transactions, vec![tx]);
}

#[tokio::test]
async fn original_primary_error_is_returned_when_read_fallback_fails() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().fail_reads = true;
    fallback.state.lock().unwrap().fail_reads = true;
    let error = rpc.get_feerate().await.unwrap_err().to_string();
    assert_eq!(error, "primary.invalid fee read failed");
}

#[tokio::test]
async fn original_primary_error_is_returned_when_broadcast_fallback_fails() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().fail_broadcast = true;
    fallback.state.lock().unwrap().fail_broadcast = true;
    let transaction = genesis_block(Network::Bitcoin).txdata.remove(0);
    let error = rpc.submit_transaction(transaction).await.unwrap_err();
    assert_eq!(error.to_string(), "primary.invalid broadcast rejected");
    assert_eq!(primary.calls("broadcast"), 1);
    assert_eq!(fallback.calls("broadcast"), 1);
}

async fn wait_for_failed_status_attempt(
    monitor: &ServerBitcoinRpcMonitor,
    primary: &Fake,
    fallback: &Fake,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while primary.calls("status") == 0 || fallback.calls("count") == 0 {
            fedimint_core::runtime::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("monitor should attempt a status update");
    assert!(monitor.status().is_none());
}

#[tokio::test]
async fn monitor_read_failure_does_not_suppress_broadcast() {
    let (rpc, primary, fallback) = hybrid().await;
    primary.state.lock().unwrap().fail_count = true;
    fallback.state.lock().unwrap().fail_count = true;
    let tasks = TaskGroup::new();
    let monitor = ServerBitcoinRpcMonitor::new(rpc.into_dyn(), Duration::from_millis(1), &tasks);
    wait_for_failed_status_attempt(&monitor, &primary, &fallback).await;
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
