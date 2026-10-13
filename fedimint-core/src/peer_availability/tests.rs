use std::collections::BTreeMap;

use super::{
    PEER_AVAILABILITY_WINDOWS_SECS, PeerAvailability, WindowAvailability, merge_peer_availability,
};
use crate::{NumPeers, PeerId};

fn report(coverage_bps: u16, peers: &[(u16, u16)]) -> PeerAvailability {
    PeerAvailability {
        last_seen_secs: BTreeMap::new(),
        windows: PEER_AVAILABILITY_WINDOWS_SECS
            .iter()
            .map(|window_secs| WindowAvailability {
                window_secs: *window_secs,
                coverage_bps,
                peers: peers
                    .iter()
                    .map(|(peer, bps)| (PeerId::from(*peer), *bps))
                    .collect(),
            })
            .collect(),
    }
}

#[test]
fn evil_reporters_cannot_move_the_result_outside_honest_reports() {
    // 10 peers tolerate 3 evil ones. Peer 0 is down half the time. Honest
    // peers 1..=6 report 4900..=5400 about it, evil peers 7..=9 claim 10000.
    let num_peers = NumPeers::from(10);
    let mut reports: BTreeMap<PeerId, PeerAvailability> = (1..=6)
        .map(|reporter| {
            (
                PeerId::from(reporter),
                report(10_000, &[(0, 4_800 + 100 * reporter)]),
            )
        })
        .collect();
    for evil in 7..=9 {
        reports.insert(PeerId::from(evil), report(10_000, &[(0, 10_000)]));
    }

    // Sorted: 10000 x3, 5400, 5300, ... so the 4th highest is honest 5400
    assert_eq!(
        merge_peer_availability(&reports, num_peers).windows[0][&PeerId::from(0)],
        5_400
    );

    // Evil peers claiming 0 instead cannot push it below the honest range
    for evil in 7..=9 {
        reports.insert(PeerId::from(evil), report(10_000, &[(0, 0)]));
    }
    assert_eq!(
        merge_peer_availability(&reports, num_peers).windows[0][&PeerId::from(0)],
        5_100
    );
}

#[test]
fn ignores_self_reports_and_poorly_covered_reports() {
    let num_peers = NumPeers::from(4);
    let reports = BTreeMap::from([
        // Peer 0 claims to be perfect, which must not count
        (PeerId::from(0), report(10_000, &[(0, 10_000), (3, 10_000)])),
        (PeerId::from(1), report(10_000, &[(0, 2_000), (3, 9_000)])),
        (PeerId::from(2), report(10_000, &[(0, 3_000), (3, 8_000)])),
        // Peer 3 observed less than half of what the others did
        (PeerId::from(3), report(4_999, &[(0, 9_999)])),
    ]);

    let merged = merge_peer_availability(&reports, num_peers).windows;

    // max_evil() is 1, so the 2nd highest usable report: 2000 from peers 1 and 2
    assert_eq!(merged[0][&PeerId::from(0)], 2_000);
    assert_eq!(merged[0][&PeerId::from(3)], 9_000);
    // Nobody reports on peer 1
    assert!(!merged[0].contains_key(&PeerId::from(1)));
}

#[test]
fn last_seen_ignores_self_reports_and_the_most_recent_evil_ones() {
    // 4 peers tolerate 1 evil one. Peer 3 has been offline since t=100.
    let num_peers = NumPeers::from(4);
    let seen = |peer_3: u64| PeerAvailability {
        last_seen_secs: BTreeMap::from([(PeerId::from(3), peer_3)]),
        windows: vec![],
    };
    let reports = BTreeMap::from([
        (PeerId::from(0), seen(100)),
        (PeerId::from(1), seen(90)),
        // Evil peer 2 claims peer 3 was seen just now
        (PeerId::from(2), seen(1_000)),
        // Peer 3 claims the same about itself
        (PeerId::from(3), seen(1_000)),
    ]);

    assert_eq!(
        merge_peer_availability(&reports, num_peers).last_seen_secs,
        BTreeMap::from([(PeerId::from(3), 100)])
    );
}
