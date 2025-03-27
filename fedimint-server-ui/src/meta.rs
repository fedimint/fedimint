use axum::extract::{Form, State};
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::cookie::CookieJar;
use fedimint_core::module::serde_json::{self, Value};
use fedimint_meta_server::Meta;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use maud::{Markup, html};

use crate::{AuthState, check_auth};

// Form for meta value submission
#[derive(serde::Deserialize)]
pub struct MetaValueForm {
    pub json_content: String,
}

// Function to render the Meta module UI section
pub async fn render(meta: &Meta) -> Markup {
    // Get current consensus value
    let consensus_value = meta.handle_get_consensus_request_ui().await.ok().flatten();
    // Get current revision number
    let revision = meta
        .handle_get_consensus_revision_request_ui()
        .await
        .ok()
        .unwrap_or(0);
    // Get current submissions from all peers
    let submissions = meta
        .handle_get_submissions_request_ui()
        .await
        .ok()
        .unwrap_or_default();

    html! {
        // Meta Configuration Card
        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { "Meta Configuration" }
                    div class="card-body" {
                        // Current Consensus Value Section
                        div class="mb-4" {
                            h5 { "Current Consensus Value (Revision: " (revision) ")" }
                            @if let Some(value) = &consensus_value {
                                pre class="bg-light p-3 user-select-all" {
                                    code {
                                        (serde_json::to_string_pretty(value).unwrap_or_else(|_| "Invalid JSON".to_string()))
                                    }
                                }
                            } @else {
                                div class="alert alert-secondary" { "No consensus value has been established yet." }
                            }
                        }

                        // Submission Form
                        div class="mb-4" {
                            h5 { "Submit New Configuration" }
                            form method="post" action="/meta/submit" id="metaSubmitForm" {
                                div class="form-group" {
                                    label for="json_content" { "JSON Configuration" }
                                    textarea class="form-control" id="json_content" name="json_content" rows="5"
                                        placeholder="Enter valid JSON configuration" required {}
                                }
                                div class="mt-3 d-flex justify-content-between" {
                                    button type="submit" class="btn btn-primary" { "Submit Configuration" }
                                    div id="jsonValidationMessage" class="text-danger" {}
                                }
                            }
                        }

                        // Current Submissions Section
                        @if !submissions.is_empty() {
                            div {
                                h5 { "Current Peer Submissions" }
                                div class="table-responsive" {
                                    table class="table table-sm" {
                                        thead {
                                            tr {
                                                th { "Peer ID" }
                                                th { "Submitted Value" }
                                                th { "Actions" }
                                            }
                                        }
                                        tbody {
                                            @for (peer_id, value) in &submissions {
                                                tr {
                                                    td { (peer_id.to_string()) }
                                                    td {
                                                        pre class="m-0 p-2 bg-light" style="max-height: 150px; overflow-y: auto;" {
                                                            code {
                                                                (serde_json::to_string_pretty(value).unwrap_or_else(|_| "Invalid JSON".to_string()))
                                                            }
                                                        }
                                                    }
                                                    td {
                                                        form method="post" action="/meta/submit" {
                                                            input type="hidden" name="json_content" value=(serde_json::to_string(value).unwrap_or_default());
                                                            button type="submit" class="btn btn-sm btn-outline-success" {
                                                                "Accept This Submission"
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
            }
        }

        // Add JavaScript for JSON validation
        script {
            r#"
            document.addEventListener('DOMContentLoaded', function() {
                const jsonTextarea = document.getElementById('json_content');
                const jsonValidationMsg = document.getElementById('jsonValidationMessage');
                const metaForm = document.getElementById('metaSubmitForm');

                // Validate JSON when the form is submitted
                metaForm.addEventListener('submit', function(event) {
                    try {
                        const jsonContent = jsonTextarea.value.trim();
                        if (jsonContent) {
                            JSON.parse(jsonContent);
                            jsonValidationMsg.textContent = '';
                        }
                    } catch (e) {
                        event.preventDefault();
                        jsonValidationMsg.textContent = 'Invalid JSON: ' + e.message;
                    }
                });
            });
            "#
        }
    }
}

// Handler for submitting a JSON meta configuration
pub async fn submit_meta_value(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(form): Form<MetaValueForm>,
) -> impl IntoResponse {
    // Check authentication
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    let meta_module = state.api.get_module::<Meta>().unwrap();

    if let Ok(json_value) = serde_json::from_str::<Value>(&form.json_content) {
        meta_module.handle_submit_request_ui(json_value).await.ok();
    }

    Redirect::to("/").into_response()
}
