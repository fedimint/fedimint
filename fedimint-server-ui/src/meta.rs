use axum::extract::{Form, State};
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::cookie::CookieJar;
use fedimint_meta_server::Meta;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use maud::{Markup, html};

use crate::{AuthState, check_auth};

// Form for meta value submission
#[derive(serde::Deserialize)]
pub struct MetaValueForm {
    pub key: String,
    pub value: String,
}

// Function to render the Meta module UI section
pub async fn render(meta: &Meta) -> Markup {
    // Get the consensus data as a map of key-value pairs
    let consensus_map = meta
        .handle_get_consensus_request_ui()
        .await
        .unwrap_or_default();
    // Get the revision number for display
    let revision = meta
        .handle_get_consensus_revision_request_ui()
        .await
        .unwrap_or(0);
    // Get pending submissions that differ from consensus
    let pending_submissions = meta.get_submissions_differing_from_consensus_ui().await;

    html! {
        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { "Meta Module" }
                    div class="card-body" {
                        // Meta Consensus Information
                        div class="mb-4" {
                            h5 { "Consensus Information" }
                            p { "Current Revision: " span class="badge bg-info" { (revision) } }

                            @if let Some(consensus_map) = consensus_map {
                                @if !consensus_map.is_empty() {
                                    div class="table-responsive" {
                                        table class="table table-hover" {
                                            thead {
                                                tr {
                                                    th { "Key" }
                                                    th { "Value" }
                                                }
                                            }
                                            tbody {
                                                @for (key, value) in &consensus_map {
                                                    tr {
                                                        td { (key) }
                                                        td { (value) }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } @else {
                                    div class="alert alert-info" { "No consensus data yet" }
                                }
                            } @else {
                                div class="alert alert-info" { "No consensus value yet" }
                            }
                        }

                        // Pending Submissions
                        @if !pending_submissions.is_empty() {
                            div class="mb-4" {
                                h5 { "Pending Submissions" }
                                p { "These submissions differ from current consensus and are waiting for enough peers to agree:" }
                                div class="table-responsive" {
                                    table class="table table-hover" {
                                        thead {
                                            tr {
                                                th { "Peer ID" }
                                                th { "Key" }
                                                th { "Value" }
                                                th { "Actions" }
                                            }
                                        }
                                        tbody {
                                            @for (peer_id, (key, value)) in &pending_submissions {
                                                tr {
                                                    td { (peer_id) }
                                                    td { (key) }
                                                    td { (value) }
                                                    td {
                                                        form method="post" action="/meta/submit" class="d-inline" {
                                                            input type="hidden" name="key" value=(key);
                                                            input type="hidden" name="value" value=(value);
                                                            button type="submit" class="btn btn-sm btn-primary" {
                                                                "Accept"
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

                        // Meta Submit Form
                        div class="mt-4" {
                            h5 { "Add or Update Meta Value" }
                            form method="post" action="/meta/submit" {
                                div class="row g-3" {
                                    div class="col-md-5" {
                                        div class="form-group" {
                                            label for="meta_key" class="form-label" { "Key" }
                                            div class="input-group" {
                                                select class="form-select" id="key_dropdown" onchange="updateKeyInput(this.value)" {
                                                    option value="" { "Select common key" }
                                                    option value="welcome_message" { "welcome_message" }
                                                    option value="federation_expiry_timestamp" { "federation_expiry_timestamp" }
                                                    option value="federation_name" { "federation_name" }
                                                }
                                                input type="text" class="form-control" id="meta_key" name="key" required;
                                            }
                                        }
                                    }
                                    div class="col-md-5" {
                                        div class="form-group" {
                                            label for="meta_value" class="form-label" { "Value" }
                                            input type="text" class="form-control" id="meta_value" name="value" required;
                                        }
                                    }
                                    div class="col-md-2" {
                                        label class="form-label" style="visibility:hidden" { "Submit" }
                                        button type="submit" class="btn btn-primary w-100" { "Submit" }
                                    }
                                }
                            }

                            // JavaScript to handle key selection and custom input
                            script {
                                r#"
                                function updateKeyInput(value) {
                                    const keyInput = document.getElementById('meta_key');
                                    // Always set the input value to the selected option
                                    keyInput.value = value;
                                }

                                // Initialize with empty value
                                document.addEventListener('DOMContentLoaded', function() {
                                    document.getElementById('meta_key').value = '';
                                });
                                "#
                            }
                        }
                    }
                }
            }
        }
    }
}

// Handler for submitting a new meta value
pub async fn submit_meta_value(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(form): Form<MetaValueForm>,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    if let Some(meta_module) = state.api.get_module::<Meta>() {
        // Submit the new value
        if let Err(e) = meta_module
            .handle_submit_request_ui(form.key, form.value)
            .await
        {
            // Log error but continue
            eprintln!("Error submitting meta value: {:?}", e);
        }
    }

    Redirect::to("/").into_response()
}
