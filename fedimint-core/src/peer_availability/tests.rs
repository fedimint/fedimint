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

    // Sorted: 4900, 5000, 5100, 5200, ..., 10000 x3, so the 4th lowest is
    // honest 5200
    assert_eq!(
        merge_peer_availability(&reports, num_peers).windows[0][&PeerId::from(0)],
        5_200
    );

    // Evil peers claiming 0 instead cannot push it below the honest range
    for evil in 7..=9 {
        reports.insert(PeerId::from(evil), report(10_000, &[(0, 0)]));
    }
    assert_eq!(
        merge_peer_availability(&reports, num_peers).windows[0][&PeerId::from(0)],
        4_900
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

    // max_evil() is 1, so the 2nd lowest usable report: 3000 from peers 1 and 2
    assert_eq!(merged[0][&PeerId::from(0)], 3_000);
    assert_eq!(merged[0][&PeerId::from(3)], 9_000);
    // Nobody reports on peer 1
    assert!(!merged[0].contains_key(&PeerId::from(1)));
}

#[test]
fn evil_reporter_claiming_full_coverage_cannot_exclude_equally_covered_honest_reports() {
    // A young federation: honest peers observed 30% of the window so far,
    // evil peer 3 claims full coverage to make them look poorly covered.
    let num_peers = NumPeers::from(4);
    let reports = BTreeMap::from([
        (PeerId::from(0), report(3_000, &[(1, 9_000), (2, 9_000)])),
        (PeerId::from(1), report(3_000, &[(0, 8_000), (2, 7_000)])),
        (PeerId::from(2), report(3_000, &[(0, 6_000), (1, 5_000)])),
        (PeerId::from(3), report(u16::MAX, &[(0, 0), (1, 0), (2, 0)])),
    ]);

    let merged = merge_peer_availability(&reports, num_peers).windows;

    assert_eq!(
        merged[0],
        BTreeMap::from([
            (PeerId::from(0), 6_000),
            (PeerId::from(1), 5_000),
            (PeerId::from(2), 7_000),
        ])
    );
}

#[test]
fn with_too_few_reports_an_evil_reporter_cannot_lower_a_value() {
    // Peer 0 is up. Honest peer 3 observed little, so its report is not
    // usable, and evil peer 2 claims peer 0 was never up.
    let num_peers = NumPeers::from(4);
    let mut reports = BTreeMap::from([
        (PeerId::from(1), report(10_000, &[(0, 9_000)])),
        (PeerId::from(2), report(10_000, &[(0, 0)])),
        (PeerId::from(3), report(4_999, &[(0, 9_000)])),
    ]);
    // Peer 3's last-seen entry for peer 0 is missing, evil peer 2 claims 0
    for (reporter, last_seen) in [(1, Some(1_000)), (2, Some(0)), (3, None)] {
        reports
            .get_mut(&PeerId::from(reporter))
            .unwrap()
            .last_seen_secs = last_seen
            .map(|secs| (PeerId::from(0), secs))
            .into_iter()
            .collect();
    }

    let merged = merge_peer_availability(&reports, num_peers);

    assert_eq!(merged.windows[0][&PeerId::from(0)], 9_000);
    assert_eq!(merged.last_seen_secs[&PeerId::from(0)], 1_000);
}

#[test]
fn ignores_windows_of_other_lengths() {
    let num_peers = NumPeers::from(4);
    let mut reports: BTreeMap<PeerId, PeerAvailability> = (1..=3)
        .map(|reporter| (PeerId::from(reporter), report(10_000, &[(0, 9_000)])))
        .collect();
    reports.get_mut(&PeerId::from(1)).unwrap().windows[0].window_secs = 86_400;
    reports.get_mut(&PeerId::from(2)).unwrap().windows[0].window_secs = 86_400;

    let merged = merge_peer_availability(&reports, num_peers).windows;

    assert!(!merged[0].contains_key(&PeerId::from(0)));
    assert_eq!(merged[1][&PeerId::from(0)], 9_000);
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
