use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_core::PeerId;
use fedimint_server_core::dashboard_ui::P2PConnectionStatus;
use maud::{Markup, html};

pub fn render(
    consensus_ord_latency: Option<Duration>,
    p2p_connection_status: &BTreeMap<PeerId, Option<P2PConnectionStatus>>,
) -> Markup {
    html! {
        div class="card h-100" id="consensus-latency" {
            div class="card-header dashboard-header" { "System Latency" }
            div class="card-body" {
                @if let Some(duration) = consensus_ord_latency {
                    div class=(format!("alert {}", if duration.as_millis() < 1000 {
                        "alert-success"
                    } else if duration.as_millis() < 2000 {
                        "alert-warning"
                    } else {
                        "alert-danger"
                    })) {
                        "Consensus Latency: " strong {
                            (format!("{} ms", duration.as_millis()))
                        }
                    }
                }
                @if p2p_connection_status.is_empty() {
                    p { "No peer connections available." }
                } @else {
                    table class="table table-striped" {
                        thead {
                            tr {
                                th { "ID" }
                                th { "Status" }
                                th { "Direct" }
                                th { "Relay" }
                                th { "Round Trip" }
                            }
                        }
                        tbody {
                            @for (peer_id, status) in p2p_connection_status {
                                tr {
                                    td { (peer_id.to_string()) }
                                    td {
                                        @match status {
                                            Some(_) => {
                                                span class="badge bg-success" { "Connected" }
                                            }
                                            None => {
                                                span class="badge bg-danger" { "Disconnected" }
                                            }
                                        }
                                    }
                                    td {
                                        (path_badge(status.as_ref().and_then(|s| s.paths).map(|p| p.direct)))
                                    }
                                    td {
                                        (path_badge(status.as_ref().and_then(|s| s.paths).map(|p| p.relay)))
                                    }
                                    td {
                                        @match status.as_ref().and_then(|s| s.rtt) {
                                            Some(duration) => {
                                                (format!("{} ms", duration.as_millis()))
                                            }
                                            None => {
                                                span class="text-muted" { "N/A" }
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
}

/// Renders a yes/no badge for a transport path's availability, or "N/A" when
/// the path information is not known (e.g. the peer is disconnected).
fn path_badge(available: Option<bool>) -> Markup {
    html! {
        @match available {
            Some(true) => {
                span class="badge bg-success" { "Yes" }
            }
            Some(false) => {
                span class="badge bg-secondary" { "No" }
            }
            None => {
                span class="text-muted" { "N/A" }
            }
        }
    }
}
