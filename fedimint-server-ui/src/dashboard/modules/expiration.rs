use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Response};
use chrono::{Datelike, TimeZone, Utc};
use fedimint_core::PeerId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::serde_json::{self, Value};
use fedimint_meta_server::Meta;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{Markup, html};
use tracing::warn;

use super::meta::{RequestError, RequestResult, render_submissions_form};
use crate::LOG_UI;

// Expiration route constants
pub const EXPIRATION_SUBMIT_ROUTE: &str = "/expiration/submit";
pub const EXPIRATION_APPROVE_ROUTE: &str = "/expiration/approve";

// Meta keys for expiration-related data
const EXPIRY_TIMESTAMP_KEY: &str = "federation_expiry_timestamp";
const SUCCESSOR_KEY: &str = "federation_successor";

/// Extract the federation_expiry_timestamp from a meta value
pub fn get_expiry_timestamp(meta_value: &Value) -> Option<u64> {
    meta_value.get(EXPIRY_TIMESTAMP_KEY).and_then(|v| {
        // Handle both string and number representations
        match v {
            Value::String(s) => s.parse().ok(),
            Value::Number(n) => n.as_u64(),
            _ => None,
        }
    })
}

/// Extract the federation_successor from a meta value
pub fn get_successor(meta_value: &Value) -> Option<String> {
    meta_value
        .get(SUCCESSOR_KEY)
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Format a UNIX timestamp as a human-readable datetime string
fn format_timestamp(timestamp: u64) -> String {
    Utc.timestamp_opt(timestamp as i64, 0)
        .single()
        .map(|dt| dt.format("%B %d, %Y %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("Invalid timestamp: {timestamp}"))
}

/// Format a timestamp for HTML datetime-local input (YYYY-MM-DDTHH:MM)
fn format_timestamp_for_input(timestamp: u64) -> String {
    Utc.timestamp_opt(timestamp as i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M").to_string())
        .unwrap_or_default()
}

/// Get the default expiration timestamp (3 months from now, end of that month
/// at midnight UTC)
fn default_expiration_timestamp() -> u64 {
    let now = Utc::now();
    // Add 3 months
    let future = now
        .checked_add_months(chrono::Months::new(3))
        .unwrap_or(now);
    // Get the first day of the next month at midnight
    let next_month = if future.month() == 12 {
        Utc.with_ymd_and_hms(future.year() + 1, 1, 1, 0, 0, 0)
            .single()
    } else {
        Utc.with_ymd_and_hms(future.year(), future.month() + 1, 1, 0, 0, 0)
            .single()
    };
    // Subtract one second to get the end of the current month
    next_month
        .map(|dt| (dt.timestamp() - 1) as u64)
        .unwrap_or_else(|| (now.timestamp() + 90 * 24 * 60 * 60) as u64)
}

/// Validate an invite code string
fn validate_invite_code(code: &str) -> bool {
    if code.is_empty() {
        return true; // Empty is valid (optional field)
    }
    code.parse::<InviteCode>().is_ok()
}

/// Identify keys that differ between two meta values
fn find_changed_keys(current: &Value, proposed: &Value) -> Vec<String> {
    let mut changed = Vec::new();

    let current_obj = current.as_object();
    let proposed_obj = proposed.as_object();

    if let (Some(curr), Some(prop)) = (current_obj, proposed_obj) {
        // Check for changed or added keys
        for (key, prop_val) in prop {
            if key == EXPIRY_TIMESTAMP_KEY || key == SUCCESSOR_KEY {
                continue; // Skip these, we handle them specially
            }
            match curr.get(key) {
                Some(curr_val) if curr_val != prop_val => changed.push(key.clone()),
                None => changed.push(key.clone()),
                _ => {}
            }
        }
        // Check for removed keys
        for key in curr.keys() {
            if key == EXPIRY_TIMESTAMP_KEY || key == SUCCESSOR_KEY {
                continue;
            }
            if !prop.contains_key(key) {
                changed.push(key.clone());
            }
        }
    }

    changed
}

/// Render the Federation Expiration UI card
pub async fn render(meta: &Meta, guardian_names: &BTreeMap<PeerId, String>) -> Markup {
    // Get current consensus value
    let consensus_value = meta.handle_get_consensus_request_ui().await.ok().flatten();
    // Get current submissions from all peers
    let submissions = meta
        .handle_get_submissions_request_ui()
        .await
        .ok()
        .unwrap_or_default();

    let consensus_expiry = consensus_value.as_ref().and_then(get_expiry_timestamp);
    let consensus_successor = consensus_value.as_ref().and_then(get_successor);

    // Default value for the date picker
    let default_timestamp = consensus_expiry.unwrap_or_else(default_expiration_timestamp);

    // Group proposals by their expiration-related values
    let mut proposals_by_content: BTreeMap<(Option<u64>, Option<String>), BTreeSet<PeerId>> =
        BTreeMap::new();

    for (peer_id, value) in &submissions {
        let expiry = get_expiry_timestamp(value);
        let successor = get_successor(value);

        // Skip if this is the same as consensus
        if expiry == consensus_expiry && successor == consensus_successor {
            continue;
        }

        proposals_by_content
            .entry((expiry, successor))
            .or_default()
            .insert(*peer_id);
    }

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Federation Expiration" }
            div class="card-body" {
                // Section 1: Current consensus status
                @if let Some(expiry) = consensus_expiry {
                    div class="alert alert-info mb-4" {
                        strong { "Federation scheduled to expire on:" }
                        br;
                        span class="fs-5" { (format_timestamp(expiry)) }
                        @if let Some(ref successor) = consensus_successor {
                            br;
                            br;
                            strong { "Successor federation:" }
                            br;
                            code class="user-select-all" style="word-break: break-all;" {
                                (successor)
                            }
                        }
                    }
                } @else {
                    div class="alert alert-secondary mb-4" {
                        "No expiration date has been set for this federation."
                    }
                }

                // Section 2: Proposals from other guardians
                @if !proposals_by_content.is_empty() {
                    h5 class="mb-3" { "Pending Proposals" }
                    @for ((expiry, successor), peer_ids) in &proposals_by_content {
                        @let peer_names: Vec<String> = peer_ids.iter()
                            .map(|id| guardian_names.get(id)
                                .cloned()
                                .unwrap_or_else(|| format!("Guardian {id}")))
                            .collect();
                        @let proposal_value = submissions.get(peer_ids.iter().next().expect("peer_ids is not empty"));

                        div class="card mb-3 border-warning" {
                            div class="card-body" {
                                div class="d-flex justify-content-between align-items-start" {
                                    div {
                                        strong { "Proposed by: " }
                                        (peer_names.join(", "))
                                    }
                                }
                                ul class="mb-2 mt-2" {
                                    @if let Some(exp) = expiry {
                                        li {
                                            "Set expiration to: "
                                            strong { (format_timestamp(*exp)) }
                                        }
                                    } @else if consensus_expiry.is_some() {
                                        li { "Remove expiration date" }
                                    }

                                    @if let Some(succ) = successor {
                                        li {
                                            "Recommended successor: "
                                            code class="user-select-all" { (succ) }
                                        }
                                    } @else if consensus_successor.is_some() {
                                        li { "Remove successor federation" }
                                    }

                                    // Show other changes
                                    @if let (Some(consensus), Some(proposed)) = (&consensus_value, proposal_value) {
                                        @let other_changes = find_changed_keys(consensus, proposed);
                                        @if !other_changes.is_empty() {
                                            li {
                                                "Other changes: "
                                                (other_changes.join(", "))
                                            }
                                        }
                                    }
                                }

                                @if let Some(value) = proposal_value {
                                    form method="post"
                                        hx-post=(EXPIRATION_APPROVE_ROUTE)
                                        hx-swap="none"
                                    {
                                        input type="hidden" name="json_content"
                                            value=(serde_json::to_string(value).unwrap_or_default());
                                        button type="submit" class="btn btn-success btn-sm" {
                                            "Approve This Proposal"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Section 3: Propose new values form
                hr class="my-4";
                h5 class="mb-3" { "Propose New Expiration" }
                form #expiration-form
                    method="post"
                    hx-post=(EXPIRATION_SUBMIT_ROUTE)
                    hx-swap="none"
                {
                    div class="mb-3" {
                        label for="expiry_datetime" class="form-label" { "Expiration Date (UTC)" }
                        input
                            type="datetime-local"
                            class="form-control"
                            id="expiry_datetime"
                            name="expiry_datetime"
                            value=(format_timestamp_for_input(default_timestamp));
                        div class="form-text" {
                            "The date and time when this federation will shut down."
                        }
                    }

                    div class="mb-3" {
                        label for="successor" class="form-label" { "Successor Federation (optional)" }
                        input
                            type="text"
                            class="form-control"
                            id="successor"
                            name="successor"
                            placeholder="fed11..."
                            value=(consensus_successor.as_deref().unwrap_or(""));
                        div class="form-text" {
                            "Invite code for the federation users should migrate to."
                        }
                    }

                    div class="d-flex gap-2" {
                        button type="submit" class="btn btn-primary" {
                            "Submit Proposal"
                        }
                        @if consensus_expiry.is_some() || consensus_successor.is_some() {
                            button
                                type="button"
                                class="btn btn-outline-danger"
                                hx-post=(EXPIRATION_SUBMIT_ROUTE)
                                hx-vals="{\"clear_expiration\": \"true\"}"
                                hx-swap="none"
                            {
                                "Clear Expiration"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Form data for expiration submission
#[derive(serde::Deserialize, Default)]
pub struct ExpirationForm {
    #[serde(default)]
    pub expiry_datetime: String,
    #[serde(default)]
    pub successor: String,
    #[serde(default)]
    pub clear_expiration: String,
}

/// Form data for approving a proposal
#[derive(serde::Deserialize)]
pub struct ApproveForm {
    pub json_content: String,
}

/// Handle submission of a new expiration proposal
pub async fn post_submit_expiration(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<ExpirationForm>,
) -> RequestResult<Response> {
    let meta_module = state
        .api
        .get_module::<Meta>()
        .expect("Meta module must exist if expiration routes are registered");

    // Get the current consensus to preserve other keys
    let consensus_value = meta_module
        .handle_get_consensus_request_ui()
        .await
        .ok()
        .flatten();

    let mut new_value = if let Some(Value::Object(obj)) = consensus_value {
        obj
    } else {
        serde_json::Map::new()
    };

    // Handle clear expiration request
    if form.clear_expiration == "true" {
        new_value.remove(EXPIRY_TIMESTAMP_KEY);
        new_value.remove(SUCCESSOR_KEY);
    } else {
        // Parse the datetime string and convert to UNIX timestamp
        if !form.expiry_datetime.is_empty() {
            if let Ok(dt) =
                chrono::NaiveDateTime::parse_from_str(&form.expiry_datetime, "%Y-%m-%dT%H:%M")
            {
                let timestamp = dt.and_utc().timestamp();
                if 0 < timestamp {
                    new_value.insert(
                        EXPIRY_TIMESTAMP_KEY.to_string(),
                        Value::String(timestamp.to_string()),
                    );
                }
            } else {
                return Err(RequestError::BadRequest {
                    source: anyhow::anyhow!("Invalid datetime format"),
                });
            }
        }

        // Handle successor invite code
        let successor = form.successor.trim();
        if !successor.is_empty() {
            if !validate_invite_code(successor) {
                return Err(RequestError::BadRequest {
                    source: anyhow::anyhow!("Invalid invite code format"),
                });
            }
            new_value.insert(
                SUCCESSOR_KEY.to_string(),
                Value::String(successor.to_string()),
            );
        } else {
            new_value.remove(SUCCESSOR_KEY);
        }
    }

    let new_value = Value::Object(new_value);

    meta_module
        .handle_submit_request_ui(new_value.clone())
        .await
        .inspect_err(|msg| warn!(target: LOG_UI, msg = %msg.message, "Request error"))
        .map_err(|_err| RequestError::InternalError)?;

    // Get updated submissions and re-render
    let mut submissions = meta_module
        .handle_get_submissions_request_ui()
        .await
        .ok()
        .unwrap_or_default();

    submissions.insert(meta_module.our_peer_id, new_value);

    let content = html! {
        (render_submissions_form(meta_module.our_peer_id, &submissions))
    };
    Ok(Html(content.into_string()).into_response())
}

/// Handle approval of another guardian's proposal
pub async fn post_approve_proposal(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<ApproveForm>,
) -> RequestResult<Response> {
    let meta_module = state
        .api
        .get_module::<Meta>()
        .expect("Meta module must exist if expiration routes are registered");

    let value: Value = serde_json::from_str(&form.json_content)
        .map_err(|e| RequestError::BadRequest { source: e.into() })?;

    meta_module
        .handle_submit_request_ui(value.clone())
        .await
        .inspect_err(|msg| warn!(target: LOG_UI, msg = %msg.message, "Request error"))
        .map_err(|_err| RequestError::InternalError)?;

    // Get updated submissions and re-render
    let mut submissions = meta_module
        .handle_get_submissions_request_ui()
        .await
        .ok()
        .unwrap_or_default();

    submissions.insert(meta_module.our_peer_id, value);

    let content = html! {
        (render_submissions_form(meta_module.our_peer_id, &submissions))
    };
    Ok(Html(content.into_string()).into_response())
}
