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

use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
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

use super::db::PeerAvailabilityKey;

#[derive(Clone, Copy)]
struct AvailabilityTiming {
    slot_secs: u64,
    persist_interval: Duration,
}

impl AvailabilityTiming {
    fn for_test_env(test_env: bool) -> Self {
        if test_env {
            Self {
                slot_secs: 5,
                persist_interval: Duration::from_secs(1),
            }
        } else {
            Self {
                slot_secs: 60,
                persist_interval: Duration::from_secs(600),
            }
        }
    }
}

/// Folds the [`PeerActivity`] into the persisted [`PeerAvailabilityState`]
/// every 10 minutes, or every second in tests. A restart loses at most one
/// interval of activity.
pub async fn persist_peer_availability(db: Database, peer_activity: Arc<Mutex<PeerActivity>>) {
    let interval = AvailabilityTiming::for_test_env(is_running_in_test_env()).persist_interval;

    loop {
        sleep(interval).await;

        let now_secs = duration_since_epoch().as_secs();
        let activity = peer_activity.lock().expect("poisoned").take(now_secs);

        debug!(target: LOG_CONSENSUS, ?activity, "Peer activity since last update");

        let mut dbtx = db.begin_transaction().await;
        let mut state = dbtx
            .get_value(&PeerAvailabilityKey)
            .await
            .unwrap_or_default();
        state.update(now_secs, &activity);
        dbtx.insert_entry(&PeerAvailabilityKey, &state).await;
        dbtx.commit_tx().await;
    }
}

/// Slots of consensus traffic per peer since the last [`PeerActivity::take`].
#[derive(Debug)]
pub struct PeerActivity {
    identity: PeerId,
    num_peers: NumPeers,
    slot_secs: u64,
    slot: u64,
    heard_in_slot: BTreeSet<PeerId>,
    observed_slots: u32,
    active_slots: BTreeMap<PeerId, u32>,
    last_heard_secs: BTreeMap<PeerId, u64>,
}

/// What [`PeerActivity`] observed since it was last taken.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObservedActivity {
    pub observed_secs: u64,
    /// Each peer's share of the observed slots in `0.0..=1.0`
    pub availability: BTreeMap<PeerId, f64>,
    pub last_heard_secs: BTreeMap<PeerId, u64>,
}

impl PeerActivity {
    pub fn new(identity: PeerId, num_peers: NumPeers) -> Self {
        Self::with_timing(
            identity,
            num_peers,
            AvailabilityTiming::for_test_env(is_running_in_test_env()),
        )
    }

    fn with_timing(identity: PeerId, num_peers: NumPeers, timing: AvailabilityTiming) -> Self {
        Self {
            identity,
            num_peers,
            slot_secs: timing.slot_secs,
            slot: 0,
            heard_in_slot: BTreeSet::new(),
            observed_slots: 0,
            active_slots: BTreeMap::new(),
            last_heard_secs: BTreeMap::new(),
        }
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
        let mut active_slots = std::mem::take(&mut self.active_slots);

        // We were up in every slot we observed
        active_slots.insert(self.identity, observed_slots);
        if 0 < observed_slots {
            self.last_heard_secs.insert(self.identity, now_secs);
        }

        ObservedActivity {
            observed_secs: u64::from(observed_slots) * self.slot_secs,
            availability: self
                .num_peers
                .peer_ids()
                .filter(|_| 0 < observed_slots)
                .map(|peer| {
                    let active = active_slots.get(&peer).copied().unwrap_or(0);
                    (peer, f64::from(active) / f64::from(observed_slots))
                })
                .collect(),
            last_heard_secs: self.last_heard_secs.clone(),
        }
    }

    /// Closes the current slot once `now_secs` is past it. Slots in which
    /// nothing at all arrived are not observed.
    fn advance(&mut self, now_secs: u64) {
        let slot = now_secs / self.slot_secs;
        if slot == self.slot {
            return;
        }

        // We never hear from ourselves
        if self.num_peers.threshold() - 1 <= self.heard_in_slot.len() {
            self.observed_slots += 1;
            for peer in &self.heard_in_slot {
                *self.active_slots.entry(*peer).or_default() += 1;
            }
        }

        self.heard_in_slot.clear();
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
