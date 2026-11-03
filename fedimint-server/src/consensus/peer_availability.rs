//! This guardian's view of its peers' availability.
//!
//! A peer counts as available in a 1-minute slot if it sent us any AlephBFT
//! message in it. Every running peer sends consensus traffic while the
//! federation is active, including a slow one that lags behind and still runs
//! an older session, while an offline or frozen peer, or one whose consensus
//! is stuck, sends nothing. A slot in which we heard from fewer than
//! `threshold - 1` peers means the federation was idle, or we were down or
//! cut off ourselves, so it does not count.
//!
//! [`PeerActivity`] counts slots in memory; [`persist_peer_availability`]
//! folds them every 10 minutes into exponential moving averages with the time
//! constants in [`PEER_AVAILABILITY_WINDOWS_SECS`], persisted as
//! [`PeerAvailabilityState`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fedimint_core::db::{AutocommitResultExt, Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::peer_availability::{
    PEER_AVAILABILITY_WINDOWS_SECS, PeerAvailability, WindowAvailability,
};
use fedimint_core::task::sleep;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::{NumPeers, PeerId};
use fedimint_logging::LOG_CONSENSUS;
use tracing::debug;

use super::db::{PeerAvailabilityKey, PeerAvailabilityResetsKey};

const SLOT_SECS: u64 = 60;

/// Folds the [`PeerActivity`] into the persisted [`PeerAvailabilityState`]
/// every 10 minutes, or every 10 seconds in tests. A restart loses at most one
/// interval of activity.
pub async fn persist_peer_availability(db: Database, tracker: Arc<AvailabilityTracker>) {
    let interval = if is_running_in_test_env() {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(600)
    };

    loop {
        sleep(interval).await;

        tracker.persist(&db, duration_since_epoch().as_secs()).await;
    }
}

/// Serializes resets and writes, including taking the buffered samples.
pub struct AvailabilityTracker {
    pub activity: Arc<Mutex<PeerActivity>>,
    writes: tokio::sync::Mutex<()>,
}

impl AvailabilityTracker {
    pub fn new(identity: PeerId, num_peers: NumPeers) -> Self {
        Self {
            activity: Arc::new(Mutex::new(PeerActivity::new(identity, num_peers))),
            writes: tokio::sync::Mutex::new(()),
        }
    }

    async fn persist(&self, db: &Database, now_secs: u64) {
        let _guard = self.writes.lock().await;
        let mut activity = self.activity.lock().expect("poisoned").take(now_secs);

        debug!(target: LOG_CONSENSUS, ?activity, "Peer activity since last update");

        let mut dbtx = db.begin_transaction().await;
        let mut resets = dbtx
            .get_value(&PeerAvailabilityResetsKey)
            .await
            .unwrap_or_default();
        for (peer, fresh_state) in &mut resets {
            let fresh = ObservedActivity {
                observed_secs: activity
                    .peer_observed_secs
                    .get(peer)
                    .copied()
                    .unwrap_or(activity.observed_secs),
                availability: activity
                    .availability
                    .remove(peer)
                    .map(|v| BTreeMap::from([(*peer, v)]))
                    .unwrap_or_default(),
                last_heard_secs: activity
                    .last_heard_secs
                    .remove(peer)
                    .map(|v| BTreeMap::from([(*peer, v)]))
                    .unwrap_or_default(),
                ..Default::default()
            };
            fresh_state.update(now_secs, &fresh);
        }
        let mut state = dbtx
            .get_value(&PeerAvailabilityKey)
            .await
            .unwrap_or_default();
        state.update(now_secs, &activity);
        dbtx.insert_entry(&PeerAvailabilityKey, &state).await;
        dbtx.insert_entry(&PeerAvailabilityResetsKey, &resets).await;
        dbtx.commit_tx().await;
    }

    /// Clears `peer`'s observations and starts fresh ones, also when it was
    /// reset before.
    pub async fn reset(
        &self,
        db: &Database,
        peer: PeerId,
        now_secs: u64,
    ) -> fedimint_core::db::DatabaseResult<()> {
        let _guard = self.writes.lock().await;
        db.autocommit(
            |dbtx, _| {
                let activity = self.activity.clone();
                Box::pin(async move {
                    let mut resets = dbtx
                        .get_value(&PeerAvailabilityResetsKey)
                        .await
                        .unwrap_or_default();
                    let mut state = dbtx
                        .get_value(&PeerAvailabilityKey)
                        .await
                        .unwrap_or_default();
                    state.last_seen_secs.remove(&peer);
                    for window in &mut state.availability {
                        window.remove(&peer);
                    }
                    resets.insert(peer, PeerAvailabilityState::default());
                    dbtx.insert_entry(&PeerAvailabilityKey, &state).await;
                    dbtx.insert_entry(&PeerAvailabilityResetsKey, &resets).await;
                    // Keep samples until the reset commits. The writer stays
                    // locked until this hook has cleared the buffer.
                    dbtx.on_commit(move || {
                        activity.lock().expect("poisoned").reset(peer, now_secs);
                    });
                    Ok(())
                })
            },
            None,
        )
        .await
        .unwrap_autocommit()
    }
}

pub async fn report(db: &Database, now_secs: u64) -> PeerAvailability {
    let mut dbtx = db.begin_transaction_nc().await;
    let mut report = dbtx
        .get_value(&PeerAvailabilityKey)
        .await
        .unwrap_or_default()
        .report(now_secs);
    for (peer, fresh_state) in dbtx
        .get_value(&PeerAvailabilityResetsKey)
        .await
        .unwrap_or_default()
    {
        let fresh = fresh_state.report(now_secs);
        report.last_seen_secs.extend(fresh.last_seen_secs);
        for (i, window) in report.windows.iter_mut().enumerate() {
            let coverage = fresh.windows.get(i).map_or(0, |w| w.coverage_bps);
            window.peer_coverage_bps.insert(peer, coverage);
            if let Some(fresh) = fresh.windows.get(i) {
                window.peers.extend(&fresh.peers);
            }
        }
    }
    report
}

/// Slots of consensus traffic per peer since the last [`PeerActivity::take`].
#[derive(Debug)]
pub struct PeerActivity {
    identity: PeerId,
    num_peers: NumPeers,
    slot: u64,
    heard_in_slot: BTreeSet<PeerId>,
    observed_slots: u32,
    excluded_slots: BTreeMap<PeerId, u32>,
    skip_slot: BTreeSet<PeerId>,
    active_slots: BTreeMap<PeerId, u32>,
    last_heard_secs: BTreeMap<PeerId, u64>,
}

/// What [`PeerActivity`] observed since it was last taken.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObservedActivity {
    pub observed_secs: u64,
    pub peer_observed_secs: BTreeMap<PeerId, u64>,
    /// Each peer's share of the observed slots in `0.0..=1.0`
    pub availability: BTreeMap<PeerId, f64>,
    pub last_heard_secs: BTreeMap<PeerId, u64>,
}

impl PeerActivity {
    pub fn new(identity: PeerId, num_peers: NumPeers) -> Self {
        Self {
            identity,
            num_peers,
            slot: 0,
            heard_in_slot: BTreeSet::new(),
            observed_slots: 0,
            excluded_slots: BTreeMap::new(),
            skip_slot: BTreeSet::new(),
            active_slots: BTreeMap::new(),
            last_heard_secs: BTreeMap::new(),
        }
    }

    fn reset(&mut self, peer: PeerId, now_secs: u64) {
        self.advance(now_secs);
        self.active_slots.remove(&peer);
        self.last_heard_secs.remove(&peer);
        self.excluded_slots.insert(peer, self.observed_slots);
        // Keep this slot's traffic for judging other peers, but exclude the
        // partial slot from this peer's observations.
        self.skip_slot.insert(peer);
    }

    /// Records a consensus message from `peer`.
    pub fn heard(&mut self, peer: PeerId, now_secs: u64) {
        self.advance(now_secs);
        self.heard_in_slot.insert(peer);
        self.last_heard_secs.insert(peer, now_secs);
    }

    /// Returns the activity of the slots closed since the last call.
    pub fn take(&mut self, now_secs: u64) -> ObservedActivity {
        self.advance(now_secs);

        let observed_slots = std::mem::take(&mut self.observed_slots);
        let excluded = std::mem::take(&mut self.excluded_slots);
        let observed = |peer| observed_slots - excluded.get(&peer).copied().unwrap_or(0);
        let mut active_slots = std::mem::take(&mut self.active_slots);

        // We were up in every slot we observed
        active_slots.insert(self.identity, observed(self.identity));
        if 0 < observed(self.identity) {
            self.last_heard_secs.insert(self.identity, now_secs);
        }

        ObservedActivity {
            observed_secs: u64::from(observed_slots) * SLOT_SECS,
            peer_observed_secs: excluded
                .keys()
                .map(|peer| (*peer, u64::from(observed(*peer)) * SLOT_SECS))
                .collect(),
            availability: self
                .num_peers
                .peer_ids()
                .filter(|peer| 0 < observed(*peer))
                .map(|peer| {
                    let active = active_slots.get(&peer).copied().unwrap_or(0);
                    (peer, f64::from(active) / f64::from(observed(peer)))
                })
                .collect(),
            last_heard_secs: self.last_heard_secs.clone(),
        }
    }

    /// Closes the current slot once `now_secs` is past it. Slots in which
    /// nothing at all arrived are not observed.
    fn advance(&mut self, now_secs: u64) {
        let slot = now_secs / SLOT_SECS;
        if slot <= self.slot {
            return;
        }

        // We never hear from ourselves
        if self.num_peers.threshold() - 1 <= self.heard_in_slot.len() {
            self.observed_slots += 1;
            for peer in &self.skip_slot {
                *self.excluded_slots.entry(*peer).or_default() += 1;
            }
            for peer in self.heard_in_slot.difference(&self.skip_slot) {
                *self.active_slots.entry(*peer).or_default() += 1;
            }
        }

        self.heard_in_slot.clear();
        self.skip_slot.clear();
        self.slot = slot;
    }
}

/// Moving averages of each peer's availability, one per window.
#[derive(Debug, Clone, Default, PartialEq, Encodable, Decodable)]
pub struct PeerAvailabilityState {
    updated_at_secs: u64,
    /// Last time each peer sent us a consensus message
    last_seen_secs: BTreeMap<PeerId, u64>,
    /// Per window: moving average of 1 over the time we observed
    coverage: Vec<Average>,
    /// Per window: moving average of each peer's availability
    availability: Vec<BTreeMap<PeerId, Average>>,
}

/// An `f64` stored by its bits, so the averages survive restarts exactly.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Average(f64);

impl Encodable for Average {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.0.to_bits().consensus_encode(writer)
    }
}

impl Decodable for Average {
    fn consensus_decode_partial<R: Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self(f64::from_bits(u64::consensus_decode_partial(
            reader, modules,
        )?)))
    }
}

impl PeerAvailabilityState {
    /// Folds in the activity observed since the last update.
    pub fn update(&mut self, now_secs: u64, activity: &ObservedActivity) {
        for (peer, heard) in &activity.last_heard_secs {
            let last_seen = self.last_seen_secs.entry(*peer).or_default();
            *last_seen = (*last_seen).max(*heard);
        }

        // Everything decays over the real elapsed time, but only the observed
        // part of it adds new weight
        let elapsed = now_secs.saturating_sub(self.updated_at_secs) as f64;
        let observed = activity.observed_secs as f64;

        let windows = PEER_AVAILABILITY_WINDOWS_SECS.len();
        self.coverage.resize(windows, Average::default());
        self.availability.resize(windows, BTreeMap::new());

        for (window, window_secs) in PEER_AVAILABILITY_WINDOWS_SECS.iter().enumerate() {
            let decay = (-elapsed.max(observed) / *window_secs as f64).exp();
            let gain = 1.0 - (-observed / *window_secs as f64).exp();

            self.coverage[window].0 = self.coverage[window].0 * decay + gain;

            for average in self.availability[window].values_mut() {
                average.0 *= decay;
            }

            for (peer, value) in &activity.availability {
                self.availability[window].entry(*peer).or_default().0 += gain * value;
            }
        }

        self.updated_at_secs = now_secs;
    }

    /// Returns the averages as seen at `now_secs`.
    pub fn report(&self, now_secs: u64) -> PeerAvailability {
        let elapsed = now_secs.saturating_sub(self.updated_at_secs) as f64;

        PeerAvailability {
            last_seen_secs: self.last_seen_secs.clone(),
            windows: PEER_AVAILABILITY_WINDOWS_SECS
                .iter()
                .zip(&self.coverage)
                .zip(&self.availability)
                .map(
                    |((window_secs, coverage), availability)| WindowAvailability {
                        window_secs: *window_secs,
                        // Time since the last update is unobserved, so coverage
                        // decays over it while the ratio below does not change
                        coverage_bps: to_bps(coverage.0 * (-elapsed / *window_secs as f64).exp()),
                        peer_coverage_bps: BTreeMap::new(),
                        peers: availability
                            .iter()
                            .map(|(peer, average)| (*peer, to_bps(average.0 / coverage.0)))
                            .collect(),
                    },
                )
                .collect(),
        }
    }
}

fn to_bps(value: f64) -> u16 {
    (value * 10_000.0).round().clamp(0.0, 10_000.0) as u16
}

#[cfg(test)]
mod tests;
