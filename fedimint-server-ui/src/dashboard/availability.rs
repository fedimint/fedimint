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
                p class="mb-0" role="status" {
                    "Loading observations… Reload to retry."
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
                "Refresh"
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
                    "Observations unavailable. Refresh to retry."
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
                p class="small text-muted mb-2"
                    title="This guardian’s observations, not the federation’s merged estimate. Idle or locally isolated periods are excluded; these values do not prove a peer is online." {
                    "Local consensus activity · exponential averages, not uptime."
                }
                @if let Some(snapshot) = snapshot {
                    p class="small text-muted mb-2" title="Observations are persisted every 10 minutes. Refresh to fetch a new snapshot." {
                        "Updated " (timestamp(snapshot.updated_at_secs))
                    }
                    @if stale {
                        div class="alert alert-warning py-2 mb-2" role="status" {
                            "Stale snapshot · historical values only."
                        }
                    }
                } @else {
                    div class="alert alert-secondary py-2 mb-2" role="status" {
                        "Awaiting observations · first save after ≥10 min."
                    }
                }
                div class="table-responsive" {
                    table class="table table-sm table-striped text-nowrap align-middle mb-0" {
                        thead {
                            tr {
                                th scope="col" { "Guardian" }
                                @for (index, label) in ["7-day EMA", "30-day EMA"].iter().enumerate() {
                                    th scope="col" {
                                        (label)
                                        div class="small text-muted fw-normal"
                                            title="Coverage: decayed observation weight, not elapsed time. Low coverage means limited evidence, even at 100% activity." {
                                            "Coverage "
                                            br class="d-sm-none";
                                            @if let Some(window) = snapshot.and_then(|snapshot| window(snapshot, index)) {
                                                (percentage(window.coverage_bps))
                                            } @else {
                                                "—"
                                            }
                                        }
                                    }
                                }
                                th scope="col" { "Last message" }
                            }
                        }
                        tbody {
                            @for (peer, name) in names {
                                tr {
                                    th scope="row" {
                                        (name) " "
                                        span class="text-muted fw-normal" { "#" (peer.to_string()) }
                                        @if *peer == identity {
                                            span class="badge bg-secondary ms-1" { "Self" }
                                        }
                                    }
                                    @for index in 0..2 {
                                        td {
                                            @if *peer == identity {
                                                span class="text-muted" title="This guardian is not measured" { "—" }
                                            } @else if let Some(value) = snapshot
                                                .and_then(|snapshot| window(snapshot, index))
                                                .and_then(|window| window.peers.get(peer))
                                                .filter(|value| **value <= 10_000) {
                                                div class="small mb-1" {
                                                    (percentage(*value))
                                                }
                                                div class="progress" style="height: 6px; min-width: 5rem;"
                                                    role="progressbar" aria-label="Observed consensus activity"
                                                    aria-valuenow=(percentage(*value).trim_end_matches('%'))
                                                    aria-valuemin="0" aria-valuemax="100" {
                                                    div class=(if stale { "progress-bar bg-secondary" } else { "progress-bar" })
                                                        style=(format!("width: {}", percentage(*value))) {}
                                                }
                                            } @else {
                                                span class="text-muted" { "No data" }
                                            }
                                        }
                                    }
                                    td class="small" {
                                        @if *peer == identity {
                                            span class="text-muted" title="This guardian is not measured" { "—" }
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
