use std::collections::BTreeMap;

use fedimint_core::PeerId;
use maud::{Markup, html};

/// Renders the Guardian info card with federation name, session count and
/// guardian list
pub fn render(
    federation_name: &str,
    session_count: usize,
    guardian_names: &BTreeMap<PeerId, String>,
) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { (federation_name) }
            div class="card-body" {
                div id="session-count" class="alert alert-info" {
                    "Session Count: " strong { (session_count) }
                }

                table class="table table-sm mb-0" {
                    thead {
                        tr {
                            th { "Guardian ID" }
                            th { "Guardian Name" }
                        }
                    }
                    tbody {
                        @for (guardian_id, name) in guardian_names {
                            tr {
                                td { (guardian_id.to_string()) }
                                td { (name) }
                            }
                        }
                    }
                }
            }
        }
    }
}
