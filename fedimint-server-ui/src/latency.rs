use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_core::PeerId;
use maud::{Markup, html};

pub fn render(
    consensus_ord_latency: Option<Duration>,
    p2p_connection_status: &BTreeMap<PeerId, Option<Duration>>,
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
                                th { "Round Trip" }
                            }
                        }
                        tbody {
                            @for (peer_id, rtt) in p2p_connection_status {
                                tr {
                                    td { (peer_id.to_string()) }
                                    td {
                                        @match rtt {
                                            Some(_) => {
                                                span class="badge bg-success" { "Connected" }
                                            }
                                            None => {
                                                span class="badge bg-danger" { "Disconnected" }
                                            }
                                        }
                                    }
                                    td {
                                        @match rtt {
                                            Some(duration) if duration.as_millis() > 0 => {
                                                (format!("{} ms", duration.as_millis()))
                                            }
                                            Some(_) | None => {
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
