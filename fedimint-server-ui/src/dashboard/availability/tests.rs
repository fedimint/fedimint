use std::collections::BTreeMap;

use fedimint_core::PeerId;
use fedimint_core::peer_availability::{
    PEER_AVAILABILITY_WINDOWS_SECS, PeerAvailability, WindowAvailability,
};
use fedimint_server_core::dashboard_ui::DashboardPeerAvailability;

use super::{STALE_AFTER_SECS, loading, render, unavailable};

const NOW: u64 = 1_792_000_000;

fn names() -> BTreeMap<PeerId, String> {
    [
        (PeerId::from(0), "North"),
        (PeerId::from(1), "East"),
        (PeerId::from(2), "South"),
        (PeerId::from(3), "West"),
    ]
    .into_iter()
    .map(|(peer, name)| (peer, name.to_owned()))
    .collect()
}

fn snapshot() -> DashboardPeerAvailability {
    DashboardPeerAvailability {
        updated_at_secs: NOW - 120,
        report: PeerAvailability {
            last_seen_secs: [(PeerId::from(1), NOW - 150), (PeerId::from(2), NOW - 7200)].into(),
            windows: PEER_AVAILABILITY_WINDOWS_SECS
                .iter()
                .enumerate()
                .map(|(index, window_secs)| WindowAvailability {
                    window_secs: *window_secs,
                    coverage_bps: if index == 0 { 7200 } else { 2600 },
                    peer_coverage_bps: BTreeMap::new(),
                    peers: [(PeerId::from(1), 10_000), (PeerId::from(2), 8432)].into(),
                })
                .collect(),
        },
    }
}

#[test]
fn renders_local_observations_without_claiming_live_health() {
    let html = render(PeerId::from(0), &names(), Some(&snapshot()), NOW).into_string();
    for expected in [
        "This guardian’s observations",
        "exponential averages, not uptime",
        "100.00%",
        "84.32%",
        "72.00%",
        "26.00%",
        "No data",
        "This guardian is not measured",
        "Unknown",
        "7-day EMA",
        "30-day EMA",
        "Coverage ",
    ] {
        assert!(html.contains(expected), "missing {expected}");
    }
    assert!(!html.contains("bg-success"));
    assert!(!html.contains("Stale snapshot"));
    assert!(!html.contains("Page snapshot:"));
    assert!(!html.contains("observation coverage:"));
    assert!(!html.contains("Refresh observations"));
    assert!(!html.contains("Refresh"));
    assert!(!html.contains("Updated "));
    assert!(html.contains("<summary title=\"Local consensus activity"));
    assert!(html.contains("aria-label=\"About observed availability\""));
}

#[test]
fn last_message_shows_relative_age_with_exact_timestamp() {
    for (age, label) in [
        (0, "0s ago"),
        (10, "10s ago"),
        (59, "59s ago"),
        (60, "1m ago"),
        (3599, "59m ago"),
        (3600, "1h ago"),
        (86399, "23h ago"),
        (86400, "1d ago"),
    ] {
        let mut snapshot = snapshot();
        snapshot
            .report
            .last_seen_secs
            .insert(PeerId::from(1), NOW - age);
        let html = render(PeerId::from(0), &names(), Some(&snapshot), NOW).into_string();
        let exact = super::timestamp(NOW - age);
        assert!(html.contains(&format!("<summary title=\"{exact}\">{label}</summary>")));
        assert!(html.contains(&format!("<span class=\"d-block\">{exact}</span>")));
    }
}

#[test]
fn startup_and_empty_windows_are_not_perfect_availability() {
    let empty = DashboardPeerAvailability {
        updated_at_secs: NOW,
        report: PeerAvailability::default(),
    };
    for snapshot in [None, Some(&empty)] {
        let html = render(PeerId::from(0), &names(), snapshot, NOW).into_string();
        assert!(!html.contains("100.00%"));
        assert!(!html.contains("role=\"progressbar\""));
        assert!(html.contains("No data"));
        assert!(html.contains("Unknown"));
    }
    assert!(
        render(PeerId::from(0), &names(), None, NOW)
            .into_string()
            .contains("Awaiting observations")
    );
}

#[test]
fn stale_and_future_snapshots_are_explicitly_historical() {
    for updated_at_secs in [0, NOW - STALE_AFTER_SECS - 1, NOW + 1] {
        let mut snapshot = snapshot();
        snapshot.updated_at_secs = updated_at_secs;
        let html = render(PeerId::from(0), &names(), Some(&snapshot), NOW).into_string();
        assert!(html.contains("Stale snapshot · historical values only."));
        assert!(html.contains("84.32%"));
        assert!(html.contains("progress-bar bg-secondary"));
    }
}

#[test]
fn invalid_or_zero_coverage_does_not_show_a_score() {
    for coverage_bps in [0, 10_001] {
        let mut snapshot = snapshot();
        for window in &mut snapshot.report.windows {
            window.coverage_bps = coverage_bps;
        }
        let html = render(PeerId::from(0), &names(), Some(&snapshot), NOW).into_string();
        assert!(html.contains("Coverage <br class=\"d-sm-none\">—"));
        assert!(!html.contains("role=\"progressbar\""));
    }
    let mut snapshot = snapshot();
    for window in &mut snapshot.report.windows {
        window.window_secs = 1;
    }
    assert!(
        !render(PeerId::from(0), &names(), Some(&snapshot), NOW)
            .into_string()
            .contains("role=\"progressbar\"")
    );
}

#[test]
fn reset_peers_show_their_own_coverage_and_new_observations() {
    let names = [(PeerId::from(1), "East".to_owned())].into();
    for shared_coverage in [0, 7200] {
        let mut snapshot = snapshot();
        for window in &mut snapshot.report.windows {
            window.coverage_bps = shared_coverage;
            window.peer_coverage_bps.insert(PeerId::from(1), 10);
        }
        let html = render(PeerId::from(0), &names, Some(&snapshot), NOW).into_string();
        assert!(html.contains("100.00%"));
        assert!(html.contains("Coverage 0.10% since reset"));
        assert!(html.contains(">2m ago</summary>"));

        for coverage in [0, 10_001] {
            for window in &mut snapshot.report.windows {
                window.peer_coverage_bps.insert(PeerId::from(1), coverage);
            }
            let html = render(PeerId::from(0), &names, Some(&snapshot), NOW).into_string();
            assert!(html.contains("No data"));
            assert!(!html.contains("role=\"progressbar\""));
        }
    }
}

#[test]
fn missing_and_invalid_values_stay_unknown_and_names_are_escaped() {
    let mut snapshot = snapshot();
    snapshot
        .report
        .last_seen_secs
        .insert(PeerId::from(1), NOW + 1);
    snapshot.report.windows[0]
        .peers
        .insert(PeerId::from(1), 10_001);
    let names = [(PeerId::from(1), "<script>bad()</script>".to_owned())].into();
    let html = render(PeerId::from(0), &names, Some(&snapshot), NOW).into_string();
    assert!(html.contains("No data"));
    assert!(html.contains("Unknown"));
    assert!(!html.contains("100.01%"));
    assert!(!html.contains("<script>bad()"));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn loading_and_error_states_offer_retry_without_scores() {
    for html in [loading().into_string(), unavailable().into_string()] {
        assert!(html.contains("retry"));
        assert!(!html.contains("role=\"progressbar\""));
    }
}

#[tokio::test]
async fn uses_dashboard_cookie_authentication_including_passwordless_mode() {
    use axum::extract::FromRequestParts;
    use axum::http::Request;
    use fedimint_ui_common::UiState;
    use fedimint_ui_common::auth::UserAuth;

    let state = UiState::new((), true);
    let (mut parts, ()) = Request::new(()).into_parts();
    assert!(
        UserAuth::from_request_parts(&mut parts, &state)
            .await
            .is_err()
    );

    let request = Request::builder()
        .header(
            "cookie",
            format!("{}={}", state.auth_cookie_name, state.auth_cookie_value),
        )
        .body(())
        .unwrap();
    let (mut parts, ()) = request.into_parts();
    assert!(
        UserAuth::from_request_parts(&mut parts, &state)
            .await
            .is_ok()
    );

    let state = UiState::new((), false);
    let (mut parts, ()) = Request::new(()).into_parts();
    assert!(
        UserAuth::from_request_parts(&mut parts, &state)
            .await
            .is_ok()
    );
}
