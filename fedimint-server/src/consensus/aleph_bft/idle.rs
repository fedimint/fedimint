use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aleph_bft::UnitCreationGate;
use bitcoin::hashes::{Hash, sha256};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::runtime::{JoinHandle, sleep, spawn};
use fedimint_core::{NumPeers, PeerId};
use rand::RngCore;
use tracing::{info, warn};

use crate::LOG_CONSENSUS;
use crate::consensus::aleph_bft::data_provider::UnitData;
use crate::metrics::{
    ALEPH_IDLE_CAPABLE_PEERS, ALEPH_IDLE_CONTROL_MESSAGES, ALEPH_IDLE_GATE_OPEN,
    ALEPH_IDLE_GATE_TRANSITIONS, ALEPH_IDLE_OUTSTANDING_BATCHES,
};

/// `P2PMessage::Default` extension identifier for idle-gate control messages.
pub const ALEPH_IDLE_CONTROL_V1: u64 = 0x464d_414c_4944_4c45;
const PROTOCOL_VERSION: u16 = 1;
const WORK_LEASE: Duration = Duration::from_secs(5);
const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const CAPABILITY_INTERVAL: Duration = Duration::from_secs(30);
const CAPABILITY_LEASE: Duration = Duration::from_secs(75);
const PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Process-wide submission counts that survive Aleph session boundaries.
#[derive(Default)]
pub struct SubmissionActivity {
    announced: AtomicU64,
    consumed: AtomicU64,
}

impl SubmissionActivity {
    fn announce(&self) {
        self.announced.fetch_add(1, Ordering::SeqCst);
    }

    fn consume(&self) {
        self.consumed.fetch_add(1, Ordering::SeqCst);
    }

    fn has_pending(&self) -> bool {
        self.consumed.load(Ordering::SeqCst) < self.announced.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests;

/// Versioned control data carried in the backwards-decodable default envelope.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub enum IdleControlV1 {
    /// Advertise support for this experimental protocol.
    Capability {
        protocol: u16,
        session: u64,
        boot_id: [u8; 16],
    },
    /// Renew a current-session work activation.
    Work {
        session: u64,
        boot_id: [u8; 16],
        generation: u64,
    },
    /// Advisory receipt acknowledgment. It never controls progress.
    Ack {
        session: u64,
        boot_id: [u8; 16],
        generation: u64,
    },
}

#[derive(Clone, Copy)]
struct PeerWork {
    boot_id: [u8; 16],
    generation: u64,
    deadline: Instant,
}

struct State {
    capabilities: BTreeMap<PeerId, ([u8; 16], Instant)>,
    peer_work: BTreeMap<PeerId, PeerWork>,
    generation: u64,
    local_active: bool,
    item_hashes: BTreeSet<sha256::Hash>,
    batches: BTreeMap<sha256::Hash, Vec<sha256::Hash>>,
    gate_open: bool,
    force_open: bool,
}

/// Coordinates the experimental gate across submission, P2P, and finalization.
#[derive(Clone)]
pub struct IdleCoordinator {
    enabled: bool,
    session: u64,
    identity: PeerId,
    num_peers: NumPeers,
    boot_id: [u8; 16],
    gate: UnitCreationGate,
    submission_activity: Option<Arc<SubmissionActivity>>,
    state: Arc<Mutex<State>>,
}

/// Owns both tasks whose lifetime is restricted to one Aleph session.
pub(crate) struct IdleSessionTasks(Vec<JoinHandle<()>>);

impl IdleSessionTasks {
    /// Start the submission observer and control-message loop when enabled.
    pub(crate) fn start(
        idle: IdleCoordinator,
        submissions: async_channel::Receiver<ConsensusItem>,
        submission_wake: Option<tokio::sync::watch::Receiver<u64>>,
        connections: DynP2PConnections<fedimint_core::config::P2PMessage>,
        shutdown: tokio::sync::watch::Receiver<Option<u64>>,
        signature: tokio::sync::watch::Receiver<
            Option<fedimint_core::secp256k1::schnorr::Signature>,
        >,
    ) -> Self {
        if !idle.enabled() {
            return Self(Vec::new());
        }
        let submission_wake =
            submission_wake.expect("enabled idle gate has a submission notification channel");
        let observer = spawn(
            "aleph idle submission observer",
            observe_submissions(submissions, submission_wake, idle.clone()),
        );
        let control = spawn("aleph idle control", {
            let idle = idle.clone();
            async move {
                idle.run_control_loop(connections, shutdown, signature)
                    .await;
            }
        });
        Self(vec![observer, control])
    }

    /// Abort and join every session-scoped task before the next session starts.
    pub(crate) async fn stop(&mut self) {
        for task in self.0.drain(..) {
            task.abort();
            task.await.ok();
        }
    }
}

impl Drop for IdleSessionTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

impl IdleCoordinator {
    /// Construct a session-scoped coordinator.
    pub fn new(
        enabled: bool,
        recovery: bool,
        session: u64,
        identity: PeerId,
        num_peers: NumPeers,
        submission_activity: Option<Arc<SubmissionActivity>>,
    ) -> Self {
        let enabled = enabled && !recovery;
        assert!(
            !enabled || submission_activity.is_some(),
            "enabled idle gate has submission activity tracking"
        );
        let mut boot_id = [0; 16];
        rand::thread_rng().fill_bytes(&mut boot_id);
        let gate = UnitCreationGate::new();
        ALEPH_IDLE_GATE_OPEN.set(1);
        ALEPH_IDLE_CAPABLE_PEERS.set(i64::from(enabled));
        ALEPH_IDLE_OUTSTANDING_BATCHES.set(0);

        if enabled {
            warn!(
                target: LOG_CONSENSUS,
                session,
                "Experimental Aleph idle gate enabled; this can harm liveness and leaks work timing"
            );
        }

        Self {
            enabled,
            session,
            identity,
            num_peers,
            boot_id,
            gate,
            submission_activity,
            state: Arc::new(Mutex::new(State {
                capabilities: BTreeMap::from([(identity, (boot_id, Instant::now()))]),
                peer_work: BTreeMap::new(),
                generation: 0,
                local_active: false,
                item_hashes: BTreeSet::new(),
                batches: BTreeMap::new(),
                gate_open: true,
                force_open: false,
            })),
        }
    }

    /// Return the upstream unit-creation gate.
    pub fn gate(&self) -> UnitCreationGate {
        self.gate.clone()
    }

    /// Return whether control traffic and gating are enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Return this process's configured guardian identity.
    pub fn identity(&self) -> PeerId {
        self.identity
    }

    /// Permanently open this session's gate for a lifecycle-critical phase.
    pub fn fail_open(&self, reason: &'static str) {
        if !self.enabled {
            return;
        }
        let mut state = self.state.lock().expect("idle coordinator mutex poisoned");
        state.force_open = true;
        self.open_locked(&mut state, reason);
    }

    /// Admit a locally submitted item, deduplicating only while it is pending
    /// or attached to an unfinalized local batch.
    pub fn admit_item(&self, item: &ConsensusItem) -> bool {
        if let Some(activity) = &self.submission_activity {
            activity.consume();
        }
        if !self.enabled {
            return true;
        }
        let hash = item.consensus_hash::<sha256::Hash>();
        let mut state = self.state.lock().expect("idle coordinator mutex poisoned");
        if !state.item_hashes.insert(hash) {
            self.reconcile_locked(&mut state);
            return false;
        }
        if !state.local_active {
            state.generation = state.generation.saturating_add(1);
            state.local_active = true;
            self.open_locked(&mut state, "local work");
        }
        true
    }

    /// Wake unit creation when the shared submission queue becomes nonempty.
    ///
    /// This intentionally does not remove the item from the queue. The
    /// session's data provider remains its sole consumer, so cancellation
    /// and session handoff cannot lose an observed submission.
    pub fn local_submission_pending(&self) {
        if !self.enabled {
            return;
        }
        let mut state = self.state.lock().expect("idle coordinator mutex poisoned");
        if !state.local_active {
            state.generation = state.generation.saturating_add(1);
            state.local_active = true;
            self.open_locked(&mut state, "local work");
        }
    }

    /// Release an admitted item that cannot be attached to a unit.
    pub fn release_item(&self, item: &ConsensusItem) {
        if self.enabled {
            self.state
                .lock()
                .expect("idle coordinator mutex poisoned")
                .item_hashes
                .remove(&item.consensus_hash::<sha256::Hash>());
        }
    }

    /// Record the item identities attached to a local batch.
    pub fn batch_created(&self, data: &UnitData, items: &[ConsensusItem]) {
        if !self.enabled {
            return;
        }
        let UnitData::Batch(bytes) = data else {
            return;
        };
        self.state
            .lock()
            .expect("idle coordinator mutex poisoned")
            .batches
            .insert(
                sha256::Hash::hash(bytes),
                items
                    .iter()
                    .map(Encodable::consensus_hash::<sha256::Hash>)
                    .collect(),
            );
        ALEPH_IDLE_OUTSTANDING_BATCHES.set(
            self.state
                .lock()
                .expect("idle coordinator mutex poisoned")
                .batches
                .len() as i64,
        );
    }

    /// Retire a finalized local batch and permit identical proposals to retry.
    pub fn batch_finalized(&self, data: &UnitData) {
        if !self.enabled {
            return;
        }
        let UnitData::Batch(bytes) = data else {
            return;
        };
        let mut state = self.state.lock().expect("idle coordinator mutex poisoned");
        if let Some(items) = state.batches.remove(&sha256::Hash::hash(bytes)) {
            for hash in items {
                state.item_hashes.remove(&hash);
            }
        }
        ALEPH_IDLE_OUTSTANDING_BATCHES.set(state.batches.len() as i64);
        state.local_active = self.has_local_work(&state);
        self.reconcile_locked(&mut state);
    }

    /// Close the gate when negotiation and current work state allow it.
    pub fn consider_idle(&self) {
        if !self.enabled {
            return;
        }
        let mut state = self.state.lock().expect("idle coordinator mutex poisoned");
        state.local_active = self.has_local_work(&state);
        self.reconcile_locked(&mut state);
    }

    /// Process one authenticated peer control message and return an advisory
    /// ACK.
    pub fn receive(&self, peer: PeerId, message: IdleControlV1) -> Option<IdleControlV1> {
        if !self.enabled || peer == self.identity || !self.num_peers.peer_ids().any(|p| p == peer) {
            return None;
        }
        let mut state = self.state.lock().expect("idle coordinator mutex poisoned");
        match message {
            IdleControlV1::Capability {
                protocol,
                session,
                boot_id,
            } if protocol == PROTOCOL_VERSION && session == self.session => {
                let is_new = state
                    .capabilities
                    .insert(peer, (boot_id, Instant::now() + CAPABILITY_LEASE))
                    .is_none_or(|(old_boot, _)| old_boot != boot_id);
                if is_new {
                    info!(
                        target: LOG_CONSENSUS,
                        %peer,
                        compatible = state.capabilities.len(),
                        total = self.num_peers.total(),
                        "Aleph idle-gate capability received"
                    );
                }
                ALEPH_IDLE_CAPABLE_PEERS.set(state.capabilities.len() as i64);
                ALEPH_IDLE_CONTROL_MESSAGES
                    .with_label_values(&["received", "capability", "accepted"])
                    .inc();
                self.reconcile_locked(&mut state);
                None
            }
            IdleControlV1::Work {
                session,
                boot_id,
                generation,
            } if session == self.session => {
                let replace = state
                    .peer_work
                    .get(&peer)
                    .is_none_or(|old| old.boot_id != boot_id || generation >= old.generation);
                if replace {
                    state.peer_work.insert(
                        peer,
                        PeerWork {
                            boot_id,
                            generation,
                            deadline: Instant::now() + WORK_LEASE,
                        },
                    );
                    self.open_locked(&mut state, "peer work");
                }
                ALEPH_IDLE_CONTROL_MESSAGES
                    .with_label_values(&[
                        "received",
                        "work",
                        if replace { "accepted" } else { "stale" },
                    ])
                    .inc();
                Some(IdleControlV1::Ack {
                    session,
                    boot_id,
                    generation,
                })
            }
            _ => None,
        }
    }

    /// Encode an extension message using Fedimint consensus encoding.
    pub fn encode(message: &IdleControlV1) -> Vec<u8> {
        message.consensus_encode_to_vec()
    }

    /// Decode a bounded extension payload using Fedimint consensus encoding.
    pub fn decode(bytes: &[u8]) -> Option<IdleControlV1> {
        if bytes.len() > 128 {
            return None;
        }
        IdleControlV1::consensus_decode_whole(bytes, &ModuleRegistry::default()).ok()
    }

    /// Run renewable capability/work advertisements and sparse fail-open
    /// probes.
    pub async fn run_control_loop(
        &self,
        connections: DynP2PConnections<fedimint_core::config::P2PMessage>,
        shutdown: tokio::sync::watch::Receiver<Option<u64>>,
        signature: tokio::sync::watch::Receiver<
            Option<fedimint_core::secp256k1::schnorr::Signature>,
        >,
    ) {
        if !self.enabled {
            return;
        }
        let mut capability_at = None;
        let mut probe_at = Instant::now() + PROBE_INTERVAL;
        loop {
            let now = Instant::now();
            if *shutdown.borrow() == Some(self.session) {
                self.fail_open("scheduled shutdown");
            }
            if signature.borrow().is_some() {
                self.fail_open("session signature phase");
            }
            if capability_at.is_none_or(|sent| now.duration_since(sent) >= CAPABILITY_INTERVAL) {
                Self::send(
                    &connections,
                    Recipient::Everyone,
                    IdleControlV1::Capability {
                        protocol: PROTOCOL_VERSION,
                        session: self.session,
                        boot_id: self.boot_id,
                    },
                );
                capability_at = Some(now);
            }
            let work = {
                let mut state = self.state.lock().expect("idle coordinator mutex poisoned");
                state.peer_work.retain(|_, work| work.deadline > now);
                self.reconcile_locked(&mut state);
                state.local_active.then_some(state.generation)
            };
            if let Some(generation) = work {
                Self::send(
                    &connections,
                    Recipient::Everyone,
                    IdleControlV1::Work {
                        session: self.session,
                        boot_id: self.boot_id,
                        generation,
                    },
                );
            }
            if now >= probe_at {
                let mut state = self.state.lock().expect("idle coordinator mutex poisoned");
                self.open_locked(&mut state, "forced liveness probe");
                probe_at = now + PROBE_INTERVAL;
            }
            sleep(REFRESH_INTERVAL).await;
        }
    }

    fn send(
        connections: &DynP2PConnections<fedimint_core::config::P2PMessage>,
        recipient: Recipient,
        message: IdleControlV1,
    ) {
        let kind = match message {
            IdleControlV1::Capability { .. } => "capability",
            IdleControlV1::Work { .. } => "work",
            IdleControlV1::Ack { .. } => "ack",
        };
        connections.send(
            recipient,
            fedimint_core::config::P2PMessage::Default {
                variant: ALEPH_IDLE_CONTROL_V1,
                bytes: Self::encode(&message),
            },
        );
        ALEPH_IDLE_CONTROL_MESSAGES
            .with_label_values(&["sent", kind, "queued"])
            .inc();
    }

    fn reconcile_locked(&self, state: &mut State) {
        let now = Instant::now();
        state.peer_work.retain(|_, work| work.deadline > now);
        state
            .capabilities
            .retain(|peer, (_, deadline)| *peer == self.identity || *deadline > now);
        ALEPH_IDLE_CAPABLE_PEERS.set(state.capabilities.len() as i64);
        let negotiated = state.capabilities.len() == self.num_peers.total();
        let should_open =
            state.force_open || !negotiated || state.local_active || !state.peer_work.is_empty();
        if should_open {
            self.open_locked(state, "fail-open or active");
        } else if state.gate_open {
            state.gate_open = false;
            self.gate.close();
            ALEPH_IDLE_GATE_OPEN.set(0);
            ALEPH_IDLE_GATE_TRANSITIONS
                .with_label_values(&["closed", "idle"])
                .inc();
            info!(target: LOG_CONSENSUS, session = self.session, "Aleph unit creation gate closed");
        }
    }

    fn has_local_work(&self, state: &State) -> bool {
        self.submission_activity
            .as_ref()
            .is_some_and(|activity| activity.has_pending())
            || !state.batches.is_empty()
            || !state.item_hashes.is_empty()
    }

    fn open_locked(&self, state: &mut State, reason: &'static str) {
        if !state.gate_open {
            state.gate_open = true;
            self.gate.open();
            ALEPH_IDLE_GATE_OPEN.set(1);
            ALEPH_IDLE_GATE_TRANSITIONS
                .with_label_values(&["open", reason])
                .inc();
            info!(
                target: LOG_CONSENSUS,
                session = self.session,
                reason,
                "Aleph unit creation gate opened"
            );
        }
    }
}

/// Observe the shared submission queue without consuming from it.
pub(crate) async fn observe_submissions(
    source: async_channel::Receiver<ConsensusItem>,
    mut wake: tokio::sync::watch::Receiver<u64>,
    idle: IdleCoordinator,
) {
    loop {
        wake.borrow_and_update();
        if !source.is_empty()
            || idle
                .submission_activity
                .as_ref()
                .is_some_and(|activity| activity.has_pending())
        {
            idle.local_submission_pending();
        }
        if wake.changed().await.is_err() {
            return;
        }
    }
}

/// Announce each opt-in submission before forwarding it into the process-wide
/// queue, so a session transition cannot miss an enqueue-in-progress.
pub(crate) async fn forward_notified_submissions(
    source: async_channel::Receiver<ConsensusItem>,
    forwarded: async_channel::Sender<ConsensusItem>,
    notification: tokio::sync::watch::Sender<u64>,
    activity: Arc<SubmissionActivity>,
) {
    while let Ok(item) = source.recv().await {
        activity.announce();
        notification.send_modify(|generation| *generation = generation.wrapping_add(1));
        if forwarded.send(item).await.is_err() {
            return;
        }
    }
}
