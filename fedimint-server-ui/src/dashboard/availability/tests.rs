use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

use fedimint_core::PeerId;
use fedimint_core::peer_availability::{
    PEER_AVAILABILITY_WINDOWS_SECS, PeerAvailability, WindowAvailability,
};
use fedimint_server_core::dashboard_ui::DashboardPeerAvailability;
use maud::html;

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
        "not calendar-window uptime",
        "100.00%",
        "84.32%",
        "72.00%",
        "26.00%",
        "No observations",
        "Not measured",
        "Unknown",
        "Page snapshot:",
    ] {
        assert!(html.contains(expected), "missing {expected}");
    }
    assert!(!html.contains("bg-success"));
    assert!(!html.contains("Stale or invalid"));
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
        assert!(html.contains("No observations"));
        assert!(html.contains("Unknown"));
    }
    assert!(
        render(PeerId::from(0), &names(), None, NOW)
            .into_string()
            .contains("Waiting for the first")
    );
}

#[test]
fn stale_and_future_snapshots_are_explicitly_historical() {
    for updated_at_secs in [0, NOW - STALE_AFTER_SECS - 1, NOW + 1] {
        let mut snapshot = snapshot();
        snapshot.updated_at_secs = updated_at_secs;
        let html = render(PeerId::from(0), &names(), Some(&snapshot), NOW).into_string();
        assert!(html.contains("Stale or invalid observation timestamp"));
        assert!(html.contains("84.32% · historical"));
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
        assert!(html.contains("No usable observations"));
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
    assert!(html.contains("No observations"));
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

/// Export the actual renderer with synthetic public data for browser captures.
/// Set FM_AVAILABILITY_FIXTURE_DIR to a new directory before running
/// explicitly.
#[test]
#[ignore = "manual screenshot fixture export"]
fn export_browser_fixtures() {
    let directory = std::path::PathBuf::from(
        std::env::var("FM_AVAILABILITY_FIXTURE_DIR").expect("set fixture destination"),
    );
    std::fs::create_dir_all(directory.join("assets")).unwrap();
    let assets =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fedimint-ui-common/assets");
    for name in [
        "bootstrap.min.css",
        "bootstrap-icons.min.css",
        "style.css",
        "logo.png",
        "htmx.org-2.0.4.min.js",
        "bootstrap.bundle.min.js",
    ] {
        std::fs::copy(assets.join(name), directory.join("assets").join(name)).unwrap();
    }
    let mut stale = snapshot();
    stale.updated_at_secs = NOW - 3600;
    for seen in stale.report.last_seen_secs.values_mut() {
        *seen -= 3600;
    }
    for (name, card) in [
        (
            "observed",
            render(PeerId::from(0), &names(), Some(&snapshot()), NOW),
        ),
        ("startup", render(PeerId::from(0), &names(), None, NOW)),
        (
            "stale",
            render(PeerId::from(0), &names(), Some(&stale), NOW),
        ),
        ("error", unavailable()),
        ("loading", loading()),
    ] {
        let content = html! {
            div class="alert alert-info" {
                strong { "Screenshot fixture" }
                " · Synthetic guardian observations, not a live federation."
            }
            div class="row gy-4 mb-4" {
                div class="col-md-6" {
                    (crate::dashboard::general::render("Example Federation", 1234, &names()))
                }
                div class="col-md-6" {
                    (crate::dashboard::latency::render(Some(Duration::from_millis(350)), &BTreeMap::new()))
                }
            }
            (card)
        };
        let page = fedimint_ui_common::dashboard_layout(content, "screenshot fixture", None);
        std::fs::File::options()
            .create_new(true)
            .write(true)
            .open(directory.join(format!("{name}.html")))
            .unwrap()
            .write_all(page.into_string().as_bytes())
            .unwrap();
    }
}
