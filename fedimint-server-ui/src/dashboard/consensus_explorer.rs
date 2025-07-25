use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::hex;
use fedimint_core::session_outcome::{AcceptedItem, SessionStatusV2};
use fedimint_core::transaction::TransactionSignature;
use fedimint_server_core::dashboard_ui::DynDashboardApi;
use maud::{Markup, html};

use crate::UiState;
use crate::auth::UserAuth;
use crate::dashboard::dashboard_layout;

/// Handler for the consensus explorer view
pub async fn consensus_explorer_view(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    session_idx: Option<Path<u64>>,
) -> impl IntoResponse {
    let session_count = state.api.session_count().await;
    let last_sessin_idx = session_count.saturating_sub(1);

    // If a specific session index was provided, show only that session
    // Otherwise, show the current session
    let session_idx = session_idx.map(|p| p.0).unwrap_or(last_sessin_idx);

    let (_sigs, items) = match state.api.get_session_status(session_idx).await {
        SessionStatusV2::Initial => (None, vec![]),
        SessionStatusV2::Pending(items) => (None, items),
        SessionStatusV2::Complete(signed_session_outcome) => (
            Some(signed_session_outcome.signatures),
            signed_session_outcome.session_outcome.items,
        ),
    };

    let content = html! {
        div class="row mb-4" {
            div class="col-12" {
                div class="d-flex justify-content-between align-items-center" {
                    h2 { "Consensus Explorer" }
                    a href="/" class="btn btn-outline-primary" { "Back to Dashboard" }
                }
            }
        }

        div class="row mb-4" {
            div class="col-12" {
                div class="d-flex justify-content-between align-items-center" {
                    // Session navigation
                    div class="btn-group" role="group" aria-label="Session navigation" {
                        @if 0 < session_idx {
                            a href={ "/explorer/" (session_idx - 1) } class="btn btn-outline-secondary" {
                                "← Previous Session"
                            }
                        } @else {
                            button class="btn btn-outline-secondary" disabled { "← Previous Session" }
                        }

                        @if session_idx < last_sessin_idx {
                            a href={ "/explorer/" (session_idx + 1) } class="btn btn-outline-secondary" {
                                "Next Session →"
                            }
                        } @else {
                            button class="btn btn-outline-secondary" disabled { "Next Session →" }
                        }
                    }

                    // Jump to session form
                    form class="d-flex" action="javascript:void(0);" onsubmit="window.location.href='/explorer/' + document.getElementById('session-jump').value" {
                        div class="input-group" {
                            input type="number" class="form-control" id="session-jump" min="0" max=(session_count - 1) placeholder="Session #";
                            button class="btn btn-outline-primary" type="submit" { "Go" }
                        }
                    }
                }
            }
        }

        div class="row" {
            div class="col-12" {
                div class="card mb-4" {
                    div class="card-header" {
                        div class="d-flex justify-content-between align-items-center" {
                            h5 class="mb-0" { "Session #" (session_idx) }
                            span class="badge bg-primary" { (items.len()) " items" }
                        }
                    }
                    div class="card-body" {
                        @if items.is_empty() {
                            div class="alert alert-secondary" {
                                "This session contains no consensus items."
                            }
                        } @else {
                            div class="table-responsive" {
                                table class="table table-striped table-hover" {
                                    thead {
                                        tr {
                                            th { "Item #" }
                                            th { "Type" }
                                            th { "Peer" }
                                            th { "Details" }
                                        }
                                    }
                                    tbody {
                                        @for (item_idx, item) in items.iter().enumerate() {
                                            tr {
                                                td { (item_idx) }
                                                td { (format_item_type(&item.item)) }
                                                td { (item.peer) }
                                                td { (format_item_details(&item)) }
                                            }
                                        }
                                    }
                                }
                            }

                            // Display signatures if available
                            @if let Some(signatures) = _sigs {
                                div class="mt-4" {
                                    h5 { "Session Signatures" }
                                    div class="alert alert-info" {
                                        p { "This session was signed by the following peers:" }
                                        ul class="mb-0" {
                                            @for peer_id in signatures.keys() {
                                                li { "Guardian " (peer_id.to_string()) }
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
    };

    Html(dashboard_layout(content).into_string()).into_response()
}

/// Format the type of consensus item for display
fn format_item_type(item: &ConsensusItem) -> String {
    match item {
        ConsensusItem::Transaction(_) => "Transaction".to_string(),
        ConsensusItem::Module(_) => "Module".to_string(),
        ConsensusItem::Default { variant, .. } => format!("Unknown ({variant})"),
    }
}

/// Format details about a consensus item
fn format_item_details(item: &AcceptedItem) -> Markup {
    match &item.item {
        ConsensusItem::Transaction(tx) => {
            html! {
                div class="consensus-item-details" {
                    div class="mb-2" {
                        "Transaction ID: " code { (tx.tx_hash()) }
                    }
                    div class="mb-2" {
                        "Nonce: " code { (hex::encode(tx.nonce)) }
                    }

                    // Inputs section
                    details class="mb-2" {
                        summary { "Inputs: " strong { (tx.inputs.len()) } }
                        @if tx.inputs.is_empty() {
                            div class="alert alert-secondary mt-2" { "No inputs" }
                        } @else {
                            div class="table-responsive mt-2" {
                                table class="table table-sm" {
                                    thead {
                                        tr {
                                            th { "#" }
                                            th { "Module ID" }
                                            th { "Type" }
                                        }
                                    }
                                    tbody {
                                        @for (idx, input) in tx.inputs.iter().enumerate() {
                                            tr {
                                                td { (idx) }
                                                td { (input.module_instance_id()) }
                                                td { (input.to_string()) }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Outputs section
                    details class="mb-2" {
                        summary { "Outputs: " strong { (tx.outputs.len()) } }
                        @if tx.outputs.is_empty() {
                            div class="alert alert-secondary mt-2" { "No outputs" }
                        } @else {
                            div class="table-responsive mt-2" {
                                table class="table table-sm" {
                                    thead {
                                        tr {
                                            th { "#" }
                                            th { "Module ID" }
                                            th { "Type" }
                                        }
                                    }
                                    tbody {
                                        @for (idx, output) in tx.outputs.iter().enumerate() {
                                            tr {
                                                td { (idx) }
                                                td { (output.module_instance_id()) }
                                                td { (output.to_string()) }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Signature info
                    details class="mb-2" {
                        summary { "Signature Info" }
                        div class="mt-2" {
                            @match &tx.signatures {
                                TransactionSignature::NaiveMultisig(sigs) => {
                                    div { "Type: NaiveMultisig" }
                                    div { "Signatures: " (sigs.len()) }
                                }
                                TransactionSignature::Default { variant, bytes } => {
                                    div { "Type: Unknown (variant " (variant) ")" }
                                    div { "Size: " (bytes.len()) " bytes" }
                                }
                            }
                        }
                    }
                }
            }
        }
        ConsensusItem::Module(module_item) => {
            html! {
                div class="consensus-item-details" {
                    div class="mb-2" {
                        "Module Instance ID: " code { (module_item.module_instance_id()) }
                    }

                    @if let Some(kind) = module_item.module_kind() {
                        div class="mb-2" {
                            "Module Kind: " strong { (kind.to_string()) }
                        }
                    } @else {
                        div class="alert alert-warning mb-2" {
                            "Unknown Module Kind"
                        }
                    }

                    div class="mb-2" {
                        "Module Item: " code { (module_item.to_string()) }
                    }
                }
            }
        }
        ConsensusItem::Default { variant, bytes } => {
            html! {
                div class="consensus-item-details" {
                    div class="alert alert-warning mb-2" {
                        "Unknown Consensus Item Type (variant " (variant) ")"
                    }
                    div class="mb-2" {
                        "Size: " (bytes.len()) " bytes"
                    }
                    @if !bytes.is_empty() {
                        details {
                            summary { "Raw Data (Hex)" }
                            div class="mt-2" {
                                code class="user-select-all" style="word-break: break-all;" {
                                    (hex::encode(bytes))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
