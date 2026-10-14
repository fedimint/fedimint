//! Guardians' views of each other's availability.
//!
//! The public
//! [`PEER_AVAILABILITY_ENDPOINT`](crate::endpoint_constants::PEER_AVAILABILITY_ENDPOINT)
//! serves them.
//! Each guardian reports when it last saw each peer take part in consensus
//! and, per window, how much of the window it observed itself
//! (`coverage_bps`) and the fraction of that time each peer took part. A
//! single report is one guardian's opinion; clients combine the reports with
//! [`merge_peer_availability`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{NumPeers, PeerId};

/// Time constants of the availability windows in seconds: one week and 30
/// days. Whether a peer is up right now is answered by `last_seen_secs`.
pub const PEER_AVAILABILITY_WINDOWS_SECS: [u64; 2] = [604_800, 2_592_000];

/// One guardian's view of its peers' availability.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAvailability {
    /// Unix time this guardian last received a consensus message from each
    /// peer
    pub last_seen_secs: BTreeMap<PeerId, u64>,
    /// One entry per window in [`PEER_AVAILABILITY_WINDOWS_SECS`]
    pub windows: Vec<WindowAvailability>,
}

/// The combined view of several guardians, see [`merge_peer_availability`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergedPeerAvailability {
    /// Unix time each peer last sent a consensus message to the reporters
    pub last_seen_secs: BTreeMap<PeerId, u64>,
    /// Per window in [`PEER_AVAILABILITY_WINDOWS_SECS`]: each peer's
    /// availability in basis points
    pub windows: Vec<BTreeMap<PeerId, u16>>,
}

/// One guardian's view of its peers' availability over one window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowAvailability {
    /// Time constant of the moving average
    pub window_secs: u64,
    /// Share of the window this guardian observed itself, in basis points
    pub coverage_bps: u16,
    /// Share of the observed time each peer took part in consensus, in basis
    /// points
    pub peers: BTreeMap<PeerId, u16>,
}

/// Combines the reports of several guardians into one view.
///
/// A peer's own report about itself is ignored. Of the other reports the
/// [`NumPeers::one_honest`]-th lowest value is used, so
/// [`NumPeers::max_evil`] lying guardians cannot push a value below every
/// honest report. With at least [`NumPeers::threshold`] usable reports they
/// cannot push it above every honest report either. With fewer, for example
/// while a guardian is offline, they can.
///
/// For availability, windows whose `window_secs` does not match
/// [`PEER_AVAILABILITY_WINDOWS_SECS`] are ignored, and so are reports that
/// cover less than half of the [`NumPeers::one_honest`]-th best coverage.
/// A peer with fewer than [`NumPeers::one_honest`] usable reports is omitted.
pub fn merge_peer_availability(
    reports: &BTreeMap<PeerId, PeerAvailability>,
    num_peers: NumPeers,
) -> MergedPeerAvailability {
    let one_honest = num_peers.one_honest();
    // The other reporters' values about `peer`, sorted ascending
    let others = |peer: PeerId, values: &mut dyn Iterator<Item = (PeerId, u64)>| {
        let mut values: Vec<u64> = values
            .filter(|(reporter, _)| *reporter != peer)
            .map(|(_, value)| value)
            .collect();
        values.sort_unstable();
        values
    };

    let last_seen_secs = num_peers
        .peer_ids()
        .filter_map(|peer| {
            let mut values = reports.iter().filter_map(|(reporter, report)| {
                Some((*reporter, *report.last_seen_secs.get(&peer)?))
            });
            Some((peer, *others(peer, &mut values).get(one_honest - 1)?))
        })
        .collect();

    let windows = PEER_AVAILABILITY_WINDOWS_SECS
        .iter()
        .enumerate()
        .map(|(window, window_secs)| {
            let windows: Vec<(PeerId, &WindowAvailability)> = reports
                .iter()
                .filter_map(|(reporter, report)| Some((*reporter, report.windows.get(window)?)))
                .filter(|(_, window)| window.window_secs == *window_secs && 0 < window.coverage_bps)
                .collect();

            num_peers
                .peer_ids()
                .filter_map(|peer| {
                    let mut coverages = windows
                        .iter()
                        .map(|(reporter, window)| (*reporter, u64::from(window.coverage_bps)));
                    let min_coverage = others(peer, &mut coverages)
                        .iter()
                        .rev()
                        .nth(one_honest - 1)?
                        .div_ceil(2);
                    let mut values = windows
                        .iter()
                        .filter(|(_, window)| min_coverage <= u64::from(window.coverage_bps))
                        .filter_map(|(reporter, window)| {
                            Some((*reporter, u64::from(*window.peers.get(&peer)?)))
                        });
                    let value = *others(peer, &mut values).get(one_honest - 1)?;
                    Some((peer, u16::try_from(value).expect("came from a u16")))
                })
                .collect()
        })
        .collect();

    MergedPeerAvailability {
        last_seen_secs,
        windows,
    }
}

#[cfg(test)]
mod tests;
