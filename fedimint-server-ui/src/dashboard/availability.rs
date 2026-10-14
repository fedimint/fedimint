//! Local observations, deliberately separate from live connectivity and from
//! the client-side, Byzantine-bounded merged estimate.
use std::collections::BTreeMap;
use std::time::Duration;

use axum::extract::State;
use axum::response::Html;
use fedimint_core::PeerId;
use fedimint_core::peer_availability::{PEER_AVAILABILITY_WINDOWS_SECS, WindowAvailability};
use fedimint_server_core::dashboard_ui::{DashboardPeerAvailability, DynDashboardApi};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{Markup, html};

pub(crate) const ROUTE: &str = "/ui/peer-availability";
// Persistence is every ten minutes. Allow one missed interval before marking
// the snapshot stale; this is not a peer-offline threshold.
const STALE_AFTER_SECS: u64 = 20 * 60;

pub(crate) fn loading() -> Markup {
    html! {
        section class="card" id="peer-availability"
            hx-get=(ROUTE) hx-trigger="load" hx-swap="outerHTML" {
            div class="card-header dashboard-header" { "Observed availability" }
            div class="card-body" {
                p role="status" { "Loading this guardian’s observations…" }
                p class="small text-muted mb-0" {
                    "If observations do not load, reload this page to retry."
                }
            }
        }
    }
}

pub(crate) async fn view(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
) -> Html<String> {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        (
            state.api.guardian_id().await,
            state.api.guardian_names().await,
            state.api.peer_availability().await,
        )
    })
    .await;
    let now = fedimint_core::time::duration_since_epoch().as_secs();
    Html(
        match result {
            Ok((identity, names, snapshot)) => render(identity, &names, snapshot.as_ref(), now),
            Err(_) => unavailable(),
        }
        .into_string(),
    )
}

fn header() -> Markup {
    html! {
        div class="card-header dashboard-header d-flex flex-wrap gap-2 justify-content-between align-items-center" {
            span { "Observed availability" }
            button class="btn btn-outline-primary btn-sm" hx-get=(ROUTE)
                hx-target="#peer-availability" hx-swap="outerHTML" {
                "Refresh observations"
            }
        }
    }
}

fn unavailable() -> Markup {
    html! {
        section class="card" id="peer-availability" {
            (header())
            div class="card-body" {
                div class="alert alert-warning mb-0" role="status" {
                    "Observations could not be loaded. Refresh to retry; no availability conclusion can be drawn."
                }
            }
        }
    }
}

fn timestamp(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .map_or_else(
            || "Unknown timestamp".to_owned(),
            |time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        )
}

fn percentage(bps: u16) -> String {
    format!("{}.{:02}%", bps / 100, bps % 100)
}

fn window(snapshot: &DashboardPeerAvailability, index: usize) -> Option<&WindowAvailability> {
    snapshot.report.windows.get(index).filter(|window| {
        window.window_secs == PEER_AVAILABILITY_WINDOWS_SECS[index]
            && (1..=10_000).contains(&window.coverage_bps)
    })
}

fn render(
    identity: PeerId,
    names: &BTreeMap<PeerId, String>,
    snapshot: Option<&DashboardPeerAvailability>,
    now: u64,
) -> Markup {
    let stale = snapshot.is_some_and(|snapshot| {
        snapshot.updated_at_secs == 0
            || snapshot.updated_at_secs > now
            || now - snapshot.updated_at_secs > STALE_AFTER_SECS
    });
    html! {
        section class="card" id="peer-availability" {
            (header())
            div class="card-body" {
                p class="mb-2" {
                    strong { "This guardian’s observations" }
                    " · Guardian " (identity.to_string())
                }
                p class="small text-muted" {
                    "Consensus-message activity in observed one-minute slots, using exponential moving averages with 7-day and 30-day time constants — not calendar-window uptime. "
                    "Idle or locally isolated periods are excluded. This is one observer’s view, not the federation’s merged estimate or proof that a guardian is online."
                }
                @if let Some(snapshot) = snapshot {
                    p class="small text-muted" {
                        "Last persisted: " (timestamp(snapshot.updated_at_secs))
                        ". Page snapshot: " (timestamp(now)) ". Updates are persisted every 10 minutes; refresh to fetch a new snapshot."
                    }
                    @if stale {
                        div class="alert alert-warning" role="status" {
                            "Stale or invalid observation timestamp. Historical values below do not describe current availability."
                        }
                    }
                    div class="row g-2 mb-3" {
                        @for (index, label) in ["7-day", "30-day"].iter().enumerate() {
                            div class="col-sm-6" {
                                div class="border rounded p-2 small" {
                                    strong { (label) " observation coverage: " }
                                    @if let Some(window) = window(snapshot, index) {
                                        (percentage(window.coverage_bps))
                                    } @else {
                                        "No usable observations"
                                    }
                                }
                            }
                        }
                    }
                    p class="small text-muted" {
                        "Coverage is the decayed observation weight, not elapsed calendar time. Low coverage means limited evidence, even when a peer’s value is 100%."
                    }
                } @else {
                    div class="alert alert-secondary" role="status" {
                        "Waiting for the first persisted observations. This can take at least 10 minutes after startup."
                    }
                }
                p class="small text-muted d-md-none" { "Scroll the table horizontally to see all observations." }
                div class="table-responsive" {
                    table class="table table-striped align-middle mb-0" {
                        thead {
                            tr {
                                th scope="col" { "Guardian" }
                                th scope="col" { "7-day average" }
                                th scope="col" { "30-day average" }
                                th scope="col" { "Last observed message" }
                            }
                        }
                        tbody {
                            @for (peer, name) in names {
                                tr {
                                    th scope="row" {
                                        (name) " "
                                        span class="text-muted fw-normal" { "#" (peer.to_string()) }
                                        @if *peer == identity {
                                            span class="badge bg-secondary ms-1" { "This guardian" }
                                        }
                                    }
                                    @for index in 0..2 {
                                        td {
                                            @if *peer == identity {
                                                span class="text-muted" { "Not measured" }
                                            } @else if let Some(value) = snapshot
                                                .and_then(|snapshot| window(snapshot, index))
                                                .and_then(|window| window.peers.get(peer))
                                                .filter(|value| **value <= 10_000) {
                                                div class="small mb-1" {
                                                    (percentage(*value))
                                                    @if stale { " · historical" }
                                                }
                                                div class="progress" style="height: 6px; min-width: 5rem;"
                                                    role="progressbar" aria-label="Observed consensus activity"
                                                    aria-valuenow=(percentage(*value).trim_end_matches('%'))
                                                    aria-valuemin="0" aria-valuemax="100" {
                                                    div class=(if stale { "progress-bar bg-secondary" } else { "progress-bar" })
                                                        style=(format!("width: {}", percentage(*value))) {}
                                                }
                                            } @else {
                                                span class="text-muted" { "No observations" }
                                            }
                                        }
                                    }
                                    td class="small" {
                                        @if *peer == identity {
                                            span class="text-muted" { "Not measured" }
                                        } @else if let Some(seen) = snapshot
                                            .and_then(|snapshot| snapshot.report.last_seen_secs.get(peer))
                                            .filter(|seen| **seen > 0 && **seen <= now) {
                                            (timestamp(*seen))
                                        } @else {
                                            span class="text-muted" { "Unknown" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
