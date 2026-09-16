use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use fedimint_core::ChainId;
use fedimint_core::runtime::{Instant, spawn, timeout};
use fedimint_server_core::bitcoin_rpc::DynServerBitcoinRpc;

/// An endpoint's identity and read-readiness observation.
#[derive(Clone, Copy, Debug)]
pub(super) struct Status {
    /// Height-1 hash identifying the endpoint's chain.
    pub(super) chain_id: ChainId,
    /// Number of locally available blocks.
    pub(super) count: u64,
    /// Whether the endpoint is still in initial block download.
    pub(super) ibd: bool,
}

/// Observations invalidated together when an endpoint request fails.
#[derive(Debug, Default)]
struct State {
    /// Failure generation prevents an older refresh from restoring eligibility.
    generation: u64,
    /// Successfully checked identity, absent after an observed failure.
    chain_id: Option<ChainId>,
    /// Short-lived health result and its expiry.
    cache: Option<(Instant, Result<Status, String>)>,
}

/// One trusted endpoint, its remembered identity, and bounded health refreshes.
#[derive(Clone, Debug)]
pub(super) struct Backend {
    /// Stable non-secret label for diagnostics.
    pub(super) name: &'static str,
    /// The actual transport.
    pub(super) rpc: DynServerBitcoinRpc,
    /// Remember identity and health, with failure ordering.
    state: Arc<Mutex<State>>,
    /// At most one refresh may occupy a backend's blocking transport.
    slot: Arc<tokio::sync::Mutex<()>>,
    /// Total refresh deadline, including waiting for an earlier refresh.
    pub(super) deadline: Duration,
    /// Freshness window for successful health observations.
    pub(super) success_ttl: Duration,
    /// Retry delay after an unavailable endpoint.
    pub(super) failure_ttl: Duration,
}

impl Backend {
    pub(super) fn new(name: &'static str, rpc: DynServerBitcoinRpc) -> Self {
        Self {
            name,
            rpc,
            state: Arc::default(),
            slot: Arc::default(),
            deadline: Duration::from_secs(5),
            success_ttl: Duration::from_secs(5),
            failure_ttl: Duration::from_secs(30),
        }
    }

    async fn fetch_chain_id(&self) -> Result<ChainId> {
        let (cached, generation) = {
            let state = self.state.lock().expect("backend state lock poisoned");
            (state.chain_id, state.generation)
        };
        if let Some(id) = cached {
            return Ok(id);
        }
        // Bypass Esplora's process-long identity cache on recovery.
        let id = ChainId::new(self.rpc.get_block_hash(1).await?);
        let mut state = self.state.lock().expect("backend state lock poisoned");
        ensure!(
            state.generation == generation,
            "Bitcoin identity invalidated during request"
        );
        state.chain_id = Some(id);
        Ok(id)
    }

    pub(super) async fn check_identity(&self, expected: ChainId) -> Result<()> {
        let actual = self.fetch_chain_id().await?;
        ensure!(
            actual == expected,
            "Bitcoin backend chain identity mismatch: expected {expected}, got {actual}"
        );
        Ok(())
    }

    fn cached(&self) -> Option<Result<Status>> {
        self.state
            .lock()
            .expect("backend state lock poisoned")
            .cache
            .as_ref()
            .filter(|(expires, _)| Instant::now() < *expires)
            .map(|(_, result)| result.clone().map_err(anyhow::Error::msg))
    }

    fn store(&self, generation: u64, result: &Result<Status>) -> bool {
        let ttl = if result.is_ok() {
            self.success_ttl
        } else {
            self.failure_ttl
        };
        let mut state = self.state.lock().expect("backend state lock poisoned");
        if state.generation != generation {
            return false;
        }
        if result.is_err() {
            state.chain_id = None;
            state.generation = state.generation.wrapping_add(1);
        }
        state.cache = Some((
            Instant::now() + ttl,
            result
                .as_ref()
                .copied()
                .map_err(|error| format!("{error:#}")),
        ));
        true
    }

    /// Forget endpoint identity after failure, so recovery rechecks its chain.
    pub(super) fn failed(&self, error: &anyhow::Error) {
        let mut state = self.state.lock().expect("backend state lock poisoned");
        state.chain_id = None;
        state.generation = state.generation.wrapping_add(1);
        state.cache = Some((Instant::now() + self.failure_ttl, Err(format!("{error:#}"))));
    }

    async fn fetch_status(&self) -> Result<Status> {
        Ok(Status {
            chain_id: self.fetch_chain_id().await?,
            ibd: self.rpc.is_in_initial_block_download().await?,
            count: self.rpc.get_block_count().await?,
        })
    }

    /// Refresh concurrently with the other endpoint, without unbounded workers.
    pub(super) async fn status(&self) -> Result<Status> {
        if let Some(result) = self.cached() {
            return result;
        }
        let this = self.clone();
        let expires = Instant::now() + self.deadline;
        let mut task = spawn("hybrid-backend-health", async move {
            // Abort cannot interrupt Core's block_in_place; keep this guard in
            // the spawned task until it exits, preventing overlapping refreshes.
            let _guard = this.slot.lock().await;
            if let Some(result) = this.cached() {
                return result;
            }
            let generation = this
                .state
                .lock()
                .expect("backend state lock poisoned")
                .generation;
            let result = this.fetch_status().await;
            let result = if Instant::now() >= expires {
                Err(anyhow!("Bitcoin health probe timed out"))
            } else {
                result
            };
            ensure!(
                this.store(generation, &result),
                "Bitcoin health invalidated during refresh"
            );
            result
        });
        match timeout(self.deadline, &mut task).await {
            Ok(result) => result.map_err(anyhow::Error::from)?,
            Err(_) => {
                task.abort();
                let error = anyhow!("Bitcoin health probe timed out");
                self.failed(&error);
                Err(error)
            }
        }
    }
}
