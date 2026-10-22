use std::collections::BTreeMap;

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{NumPeers, PeerId};

use super::{ObservedActivity, PeerActivity, PeerAvailabilityState, SLOT_SECS};

const DAY: u64 = 86_400;

fn peer(id: u16) -> PeerId {
    PeerId::from(id)
}

#[test]
fn counts_slots_per_peer_and_skips_slots_where_we_were_cut_off() {
    // We are peer 0 of 4: a slot needs messages from 2 other peers
    let mut activity = PeerActivity::new(peer(0), NumPeers::from(4));

    for slot in 0..10 {
        let now = 1_000 + slot * SLOT_SECS;
        activity.heard(peer(1), now);
        // Peer 2 only in the first half
        if slot < 5 {
            activity.heard(peer(2), now + 1);
        }
        activity.heard(peer(3), now + 9);
    }
    // 3 slots in which only peer 1 reached us: we were cut off
    for slot in 10..13 {
        activity.heard(peer(1), 1_000 + slot * SLOT_SECS);
    }

    let observed = activity.take(1_000 + 13 * SLOT_SECS);

    assert_eq!(observed.observed_secs, 10 * SLOT_SECS);
    assert_eq!(
        observed.availability,
        BTreeMap::from([
            (peer(0), 1.0),
            (peer(1), 1.0),
            (peer(2), 0.5),
            (peer(3), 1.0)
        ])
    );
    assert_eq!(observed.last_heard_secs[&peer(1)], 1_000 + 12 * SLOT_SECS);
    assert_eq!(
        observed.last_heard_secs[&peer(2)],
        1_000 + 4 * SLOT_SECS + 1
    );

    // Taking again starts from zero
    assert_eq!(activity.take(1_000 + 14 * SLOT_SECS).observed_secs, 0);
}

/// Updates `state` every 3 minutes from `from` to `to` with all observed
/// time and peer 1 up or down.
fn run(state: &mut PeerAvailabilityState, from: u64, to: u64, peer_1_up: bool) {
    for now in (from..to).step_by(180) {
        let activity = ObservedActivity {
            observed_secs: 180,
            availability: BTreeMap::from([
                (peer(0), 1.0),
                (peer(1), if peer_1_up { 1.0 } else { 0.0 }),
            ]),
            last_heard_secs: if peer_1_up {
                BTreeMap::from([(peer(1), now)])
            } else {
                BTreeMap::new()
            },
        };
        state.update(now, &activity);
    }
}

#[test]
fn week_window_forgets_faster_than_month_window() {
    let mut state = PeerAvailabilityState::default();
    // Peer 1 is up for 20 days, then down for the last day
    run(&mut state, 180, 20 * DAY, true);
    run(&mut state, 20 * DAY, 21 * DAY, false);

    let report = state.report(21 * DAY);
    let peer_1 = |window: usize| report.windows[window].peers[&peer(1)];

    // Week window: the last day weighs 1 - e^(-1/7) = 13%, against 20
    // days covering 1 - e^(-20/7) = 94%, so ~86% up
    assert!((8_550..=8_650).contains(&peer_1(0)), "{}", peer_1(0));
    // Month window covers 1 - e^(-21/30) = 0.503, of which the up days
    // weigh e^(-1/30) - e^(-21/30) = 0.471, so ~93.5% up
    assert!((9_300..=9_400).contains(&peer_1(1)), "{}", peer_1(1));
    assert_eq!(report.windows[0].peers[&peer(0)], 10_000);

    // Peer 1 was last seen in the last update of day 20
    let last_up = (180..20 * DAY).step_by(180).last().unwrap();
    assert_eq!(report.last_seen_secs[&peer(1)], last_up);
}

#[test]
fn unobserved_time_does_not_count_against_peers() {
    let mut state = PeerAvailabilityState::default();
    run(&mut state, 180, 2 * DAY, true);
    // We are down for two days: the next update has two days elapsed but
    // only 3 minutes observed, in which peer 1 is down
    run(&mut state, 4 * DAY, 4 * DAY + 1, false);
    run(&mut state, 4 * DAY + 180, 4 * DAY + 3_600, true);

    let report = state.report(4 * DAY + 3_600);

    // Only 3 minutes of the gap count as down: ~99.8%. Counting the
    // whole gap as down would give ~44% instead
    let peer_1 = report.windows[0].peers[&peer(1)];
    assert!((9_950..=9_995).contains(&peer_1), "{peer_1}");
    // We observed 2 days and an hour, decayed: ~19% of the week window
    let coverage = report.windows[0].coverage_bps;
    assert!((1_850..=2_000).contains(&coverage), "{coverage}");
}

#[test]
fn coverage_decays_while_nothing_is_observed() {
    let mut state = PeerAvailabilityState::default();
    run(&mut state, 180, 10 * DAY, true);

    // 10 days cover 1 - e^(-10/7) = 76% of the week window
    let running = state.report(10 * DAY).windows[0].coverage_bps;
    assert!((7_550..=7_650).contains(&running), "{running}");
    // A day later without updates it decays by e^(-1/7) to 66%
    let stalled = state.report(11 * DAY).windows[0].coverage_bps;
    assert!((6_550..=6_650).contains(&stalled), "{stalled}");
}

#[test]
fn state_roundtrips_through_the_database_encoding() {
    let mut state = PeerAvailabilityState::default();
    run(&mut state, 180, DAY, true);

    let decoded = PeerAvailabilityState::consensus_decode_whole(
        &state.consensus_encode_to_vec(),
        &ModuleDecoderRegistry::default(),
    )
    .unwrap();

    assert_eq!(decoded, state);
}
