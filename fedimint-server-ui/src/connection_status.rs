use std::collections::BTreeMap;

use fedimint_core::PeerId;
use maud::{Markup, html};

pub fn render_connection_status(peer_status: &BTreeMap<PeerId, bool>) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "P2P Connection Status" }
            div class="card-body" {
                @if peer_status.is_empty() {
                    p { "No peer connections available." }
                } @else {
                    table class="table table-striped" {
                        thead {
                            tr {
                                th { "Peer ID" }
                                th { "Connection Status" }
                            }
                        }
                        tbody {
                            @for (peer_id, status) in peer_status {
                                tr {
                                    td { (peer_id.to_string()) }
                                    td {
                                        @match status {
                                            true => {
                                                span class="badge bg-success" { "Connected" }
                                            }
                                            false => {
                                                span class="badge bg-danger" { "Disconnected" }
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
