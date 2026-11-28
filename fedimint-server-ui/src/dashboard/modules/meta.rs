use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

use axum::extract::{Form, FromRequest, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use fedimint_core::PeerId;
use fedimint_core::module::serde_json::{self, Value};
use fedimint_meta_server::Meta;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use jiff::Timestamp;
use jiff::civil::DateTime as CivilDateTime;
use jiff::tz::TimeZone;
use maud::{Markup, html};
use serde::Serialize;
use thiserror::Error;
use tracing::{debug, warn};

use crate::LOG_UI;

// Meta route constants
pub const META_SUBMIT_ROUTE: &str = "/meta/submit";
pub const META_SET_ROUTE: &str = "/meta/set";
pub const META_RESET_ROUTE: &str = "/meta/reset";
pub const META_DELETE_ROUTE: &str = "/meta/delete";
pub const META_VALUE_INPUT_ROUTE: &str = "/meta/value-input";
pub const META_MERGE_ROUTE: &str = "/meta/merge";

/// The type of value expected for a well-known meta key.
enum KeyType {
    String,
    Url,
    Amount,
    DateTime,
    Json,
}

/// Schema describing a well-known meta key.
struct KeySchema {
    description: &'static str,
    value_type: KeyType,
}

// <https://fedibtc.github.io/fedi-docs/docs/fedi/meta_fields/federation-metadata-configurations>
// NOTE: If you're updating this, please update `docs/meta_fields/README.md`
static WELL_KNOWN_KEYS: LazyLock<BTreeMap<&'static str, KeySchema>> = LazyLock::new(|| {
    BTreeMap::from([
        (
            "welcome_message",
            KeySchema {
                description: "A welcome message for new users joining the federation",
                value_type: KeyType::String,
            },
        ),
        (
            "federation_expiry_timestamp",
            KeySchema {
                description: "The date and time after which the federation will shut down",
                value_type: KeyType::DateTime,
            },
        ),
        (
            "federation_name",
            KeySchema {
                description: "The human-readable name of the federation",
                value_type: KeyType::String,
            },
        ),
        (
            "federation_successor",
            KeySchema {
                description: "An invite code to a successor federation for user migration",
                value_type: KeyType::String,
            },
        ),
        (
            "meta_override_url",
            KeySchema {
                description: "A URL to a file containing overrides for meta fields",
                value_type: KeyType::Url,
            },
        ),
        (
            "vetted_gateways",
            KeySchema {
                description: "A list of gateway identifiers vetted by the federation",
                value_type: KeyType::Json,
            },
        ),
        (
            "recurringd_api",
            KeySchema {
                description: "The API URL of a recurringd instance for creating LNURLs",
                value_type: KeyType::Url,
            },
        ),
        (
            "lnaddress_api",
            KeySchema {
                description: "The API URL of a Lightning Address Server for serving LNURLs",
                value_type: KeyType::Url,
            },
        ),
        (
            "fedi:pinned_message",
            KeySchema {
                description: "",
                value_type: KeyType::String,
            },
        ),
        (
            "fedi:federation_icon_url",
            KeySchema {
                description: "",
                value_type: KeyType::Url,
            },
        ),
        (
            "fedi:tos_url",
            KeySchema {
                description: "",
                value_type: KeyType::Url,
            },
        ),
        (
            "fedi:default_currency",
            KeySchema {
                description: "",
                value_type: KeyType::String,
            },
        ),
        (
            "fedi:invite_codes_disabled",
            KeySchema {
                description: "",
                value_type: KeyType::String,
            },
        ),
        (
            "fedi:new_members_disabled",
            KeySchema {
                description: "",
                value_type: KeyType::String,
            },
        ),
        (
            "fedi:max_invoice_msats",
            KeySchema {
                description: "",
                value_type: KeyType::Amount,
            },
        ),
        (
            "fedi:max_balance_msats",
            KeySchema {
                description: "",
                value_type: KeyType::Amount,
            },
        ),
        (
            "fedi:max_stable_balance_msats",
            KeySchema {
                description: "",
                value_type: KeyType::Amount,
            },
        ),
        (
            "fedi:fedimods",
            KeySchema {
                description: "",
                value_type: KeyType::Json,
            },
        ),
        (
            "fedi:default_group_chats",
            KeySchema {
                description: "",
                value_type: KeyType::Json,
            },
        ),
        (
            "fedi:offline_wallet_disabled",
            KeySchema {
                description: "",
                value_type: KeyType::String,
            },
        ),
    ])
});

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

    let consensus_map = consensus_value
        .as_ref()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();

    let current_meta_keys = if let Some(o) = submissions
        .get(&meta.our_peer_id)
        .cloned()
        .or_else(|| consensus_value.clone())
        .and_then(|v| v.as_object().cloned())
    {
        o
    } else {
        serde_json::Map::new()
    };

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Meta Configuration" }
            div class="card-body" {
                div class="mb-4" {
                    h5 { "Current Consensus (Revision: " (revision) ")" }
                    @if consensus_value.is_some() {
                        div class="row mb-2" {
                            div class="col-md-6" {
                                strong { "Full document" }
                                pre class="m-0 p-2 bg-light" style="max-height: 40vh; overflow-y: auto;" {
                                    code {
                                        (serde_json::to_string_pretty(&consensus_map).unwrap_or_else(|_| "Invalid JSON".to_string()))
                                    }
                                }
                            }
                            div class="col-md-6" {
                                (render_consensus_summary(&consensus_map))
                            }
                        }
                    } @else {
                        div class="alert alert-secondary" { "No consensus value has been established yet." }
                    }
                    div class="mb-4" {
                        (render_meta_edit_form(&consensus_map, current_meta_keys, false, MetaEditForm::default()))
                    }

                    (render_submissions_form(meta.our_peer_id, &consensus_map, &submissions))
                }
            }
        }
    }
}

/// A single change between the consensus and a proposal.
enum MetaChange {
    Set { key: String, value: String },
    Deleted { key: String },
}

/// Computes an itemized list of changes between `consensus` and `proposal`.
fn compute_changes(
    consensus: &serde_json::Map<String, Value>,
    proposal: &serde_json::Map<String, Value>,
) -> Vec<MetaChange> {
    let mut changes = Vec::new();

    // Keys set or modified in the proposal
    for (key, new_val) in proposal {
        let changed = consensus.get(key) != Some(new_val);
        if changed {
            changes.push(MetaChange::Set {
                key: key.clone(),
                value: format_value_for_display(key, new_val),
            });
        }
    }

    // Keys deleted from consensus
    for key in consensus.keys() {
        if !proposal.contains_key(key) {
            changes.push(MetaChange::Deleted { key: key.clone() });
        }
    }

    changes
}

/// Formats a meta value for human-readable display, using the key schema when
/// available (e.g. UNIX timestamps become formatted dates).
fn format_value_for_display(key: &str, value: &Value) -> String {
    if let Some(schema) = WELL_KNOWN_KEYS.get(key) {
        match schema.value_type {
            KeyType::DateTime => {
                if let Some(ts) = value
                    .as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .and_then(|t| Timestamp::from_second(t).ok())
                {
                    return ts.strftime("%Y-%m-%d %H:%M UTC").to_string();
                }
            }
            KeyType::Amount => {
                if let Some(s) = value.as_str() {
                    return format!("{s} msats");
                }
            }
            KeyType::Json => {
                return serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
            }
            KeyType::Url | KeyType::String => {}
        }
    }

    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Renders the "Proposed changes" summary from a list of [`MetaChange`]s.
fn render_changes_summary(changes: &[MetaChange]) -> Markup {
    html! {
        strong { "Proposed changes" }
        @if changes.is_empty() {
            p class="text-muted" { "No changes" }
        } @else {
            ul class="mb-0 ps-3" {
                @for change in changes {
                    li {
                        @match change {
                            MetaChange::Set { key, value } => {
                                strong { (key) }
                                " set to "
                                em { (value) }
                            },
                            MetaChange::Deleted { key } => {
                                strong { (key) }
                                " deleted"
                            },
                        }
                    }
                }
            }
        }
    }
}

/// Renders an itemized summary of all key-value pairs in a meta map,
/// formatting values using their schema when available.
fn render_consensus_summary(map: &serde_json::Map<String, Value>) -> Markup {
    html! {
        @if map.is_empty() {
            span class="text-muted" { "No fields set" }
        } @else {
            strong { "Summary" }
            ul class="mb-0 ps-3" {
                @for (key, value) in map {
                    li {
                        strong { (key) }
                        " = "
                        em { (format_value_for_display(key, value)) }
                    }
                }
            }
        }
    }
}

fn render_submissions_form(
    our_id: PeerId,
    consensus: &serde_json::Map<String, Value>,
    submissions: &BTreeMap<PeerId, Value>,
) -> Markup {
    let mut submissions_by_value: HashMap<
        String,
        (BTreeSet<PeerId>, serde_json::Map<String, Value>),
    > = HashMap::new();

    for (peer_id, value) in submissions {
        let value_str =
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "Invalid JSON".to_string());
        let proposal_map = value.as_object().cloned().unwrap_or_default();
        let entry = submissions_by_value
            .entry(value_str)
            .or_insert_with(|| (BTreeSet::new(), proposal_map));
        entry.0.insert(*peer_id);
    }

    html! {
        div #meta-submissions hx-swap-oob=(true) {
            @if !submissions.is_empty() {
                h5 { "Current Proposals" }
                @for (value_str, (peer_ids, proposal_map)) in &submissions_by_value {
                    div class="card mb-3" {
                        div class="card-header py-2" {
                            strong { "Peers: " }
                            (peer_ids.iter()
                                .map(|n| n.to_string())
                                .collect::<Vec<String>>()
                                .join(", "))
                        }
                        div class="card-body py-2" {
                            div class="row" {
                                div class="col-md-6" {
                                    strong { "Full proposal" }
                                    pre class="m-0 p-2 bg-light" style="max-height: 40vh; overflow-y: auto;" {
                                        code { (value_str) }
                                    }
                                }
                                div class="col-md-6" {
                                    (render_changes_summary(&compute_changes(consensus, proposal_map)))
                                }
                            }
                        }
                        @if !peer_ids.contains(&our_id) {
                            div class="card-footer py-2 d-flex gap-2 justify-content-end" {
                                form method="post"
                                    hx-post=(META_SUBMIT_ROUTE)
                                    hx-swap="none"
                                {
                                    input type="hidden" name="json_content"
                                        value=(value_str);
                                    button type="submit" class="btn btn-sm btn-success" {
                                        "Accept As-Is"
                                    }
                                }
                                form method="post"
                                    hx-post=(META_MERGE_ROUTE)
                                    hx-swap="none"
                                    hx-include="#meta-edit-form [name='json_content']"
                                {
                                    input type="hidden" name="proposal_json"
                                        value=(value_str);
                                    button type="submit" class="btn btn-sm btn-primary" {
                                        "Add Changes To My Proposal"
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

// Form for meta value submission
#[derive(serde::Deserialize, Default)]
pub struct MetaEditForm {
    pub json_content: String,
    #[serde(default)]
    pub add_key: String,
    #[serde(default)]
    pub add_value: String,
    #[serde(default)]
    pub delete_key: String,
}

impl MetaEditForm {
    fn top_level_keys(&self) -> RequestResult<serde_json::Map<String, Value>> {
        Ok(
            if let Some(serde_json::Value::Object(o)) =
                serde_json::from_slice(self.json_content.as_bytes())
                    .map_err(|x| RequestError::BadRequest { source: x.into() })?
            {
                o
            } else {
                serde_json::Map::new()
            },
        )
    }
}

/// Helper to fetch the current consensus as a JSON object map.
async fn get_consensus_map(meta: &Meta) -> serde_json::Map<String, Value> {
    meta.handle_get_consensus_request_ui()
        .await
        .ok()
        .flatten()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

pub async fn post_submit(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<MetaEditForm>,
) -> RequestResult<Response> {
    let meta_module = state.api.get_module::<Meta>().unwrap();

    let top_level_keys = form.top_level_keys()?;
    let top_level_object = Value::Object(top_level_keys.clone());

    meta_module
        .handle_submit_request_ui(top_level_object.clone())
        .await
        .inspect_err(|msg| warn!(target: LOG_UI, msg= %msg.message, "Request error"))
        .map_err(|_err| RequestError::InternalError)?;

    let consensus_map = get_consensus_map(meta_module).await;

    let mut submissions = meta_module
        .handle_get_submissions_request_ui()
        .await
        .ok()
        .unwrap_or_default();

    submissions.insert(meta_module.our_peer_id, top_level_object);

    let content = html! {
        (render_meta_edit_form(&consensus_map, top_level_keys, false, MetaEditForm::default()))

        // Re-render submission with our submission added, as it will take couple of milliseconds
        // for it to get processed and it's confusing if it doesn't immediately show up.
        (render_submissions_form(meta_module.our_peer_id, &consensus_map, &submissions))
    };
    Ok(Html(content.into_string()).into_response())
}

pub async fn post_reset(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(_form): Form<MetaEditForm>,
) -> RequestResult<Response> {
    let meta_module = state.api.get_module::<Meta>().unwrap();

    let consensus_map = get_consensus_map(meta_module).await;
    let top_level_keys = consensus_map.clone();
    let top_level_object = Value::Object(top_level_keys.clone());

    meta_module
        .handle_submit_request_ui(top_level_object.clone())
        .await
        .inspect_err(|msg| warn!(target: LOG_UI, msg = %msg.message, "Request error"))
        .map_err(|_err| RequestError::InternalError)?;

    let mut submissions = meta_module
        .handle_get_submissions_request_ui()
        .await
        .ok()
        .unwrap_or_default();

    submissions.remove(&meta_module.our_peer_id);

    let content = html! {
        (render_meta_edit_form(&consensus_map, top_level_keys, false, MetaEditForm::default()))

        // Re-render submission with our submission removed, as it will take couple of milliseconds
        // for it to get processed and it's confusing if it doesn't immediately show up.
        (render_submissions_form(meta_module.our_peer_id, &consensus_map, &submissions))
    };
    Ok(Html(content.into_string()).into_response())
}

pub async fn post_set(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(mut form): Form<MetaEditForm>,
) -> RequestResult<Response> {
    let meta_module = state.api.get_module::<Meta>().unwrap();
    let consensus_map = get_consensus_map(meta_module).await;

    let mut top_level_object = form.top_level_keys()?;

    let key = form.add_key.trim();
    let raw_value = form.add_value.trim();
    let key_type = WELL_KNOWN_KEYS
        .get(key)
        .map(|s| &s.value_type)
        .unwrap_or(&KeyType::String);
    let value = convert_input_value(raw_value, key_type)?;

    top_level_object.insert(key.to_string(), value);

    form.add_key = "".into();
    form.add_value = "".into();
    let content = render_meta_edit_form(
        &consensus_map,
        top_level_object,
        true,
        MetaEditForm::default(),
    );
    Ok(Html(content.into_string()).into_response())
}

pub async fn post_delete(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(mut form): Form<MetaEditForm>,
) -> RequestResult<Response> {
    let meta_module = state.api.get_module::<Meta>().unwrap();
    let consensus_map = get_consensus_map(meta_module).await;

    let mut top_level_json = form.top_level_keys()?;

    let key = form.delete_key.trim();

    top_level_json.remove(key);
    form.delete_key = "".into();

    let content = render_meta_edit_form(&consensus_map, top_level_json, true, form);
    Ok(Html(content.into_string()).into_response())
}

#[derive(serde::Deserialize)]
pub struct MetaMergeForm {
    pub json_content: String,
    pub proposal_json: String,
}

pub async fn post_merge(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<MetaMergeForm>,
) -> RequestResult<Response> {
    let meta_module = state.api.get_module::<Meta>().unwrap();
    let consensus_map = get_consensus_map(meta_module).await;

    let mut current: serde_json::Map<String, Value> =
        if let Ok(Value::Object(o)) = serde_json::from_str(&form.json_content) {
            o
        } else {
            serde_json::Map::new()
        };

    let proposal: serde_json::Map<String, Value> =
        if let Ok(Value::Object(o)) = serde_json::from_str(&form.proposal_json) {
            o
        } else {
            serde_json::Map::new()
        };

    // Compute changes from consensus -> proposal and apply to current
    for change in &compute_changes(&consensus_map, &proposal) {
        match change {
            MetaChange::Set { key, .. } => {
                if let Some(val) = proposal.get(key) {
                    current.insert(key.clone(), val.clone());
                }
            }
            MetaChange::Deleted { key } => {
                current.remove(key);
            }
        }
    }

    let content = render_meta_edit_form(&consensus_map, current, true, MetaEditForm::default());
    Ok(Html(content.into_string()).into_response())
}

/// Renders the appropriate HTML input element for the given key type.
///
/// Always returns a single element (no nested input-groups) so it can be a
/// direct child of the main `.input-group` without breaking Bootstrap's
/// `:first-child`/`:last-child` border-radius selectors.
fn render_value_input(key_type: &KeyType, current_value: &str) -> Markup {
    match key_type {
        KeyType::Url => html! {
            input #add-value type="url" name="add_value" class="form-control"
                placeholder="https://..." aria-label="Value"
                value=(current_value) {}
        },
        KeyType::Amount => html! {
            input #add-value type="number" name="add_value" class="form-control"
                placeholder="Amount (msats)" aria-label="Value"
                value=(current_value) {}
        },
        KeyType::DateTime => {
            // Pre-fill with today at 00:00 so the time portion isn't blank
            let val = if current_value.is_empty() {
                Timestamp::now().strftime("%Y-%m-%dT00:00").to_string()
            } else {
                current_value.to_string()
            };
            html! {
                input #add-value type="datetime-local" name="add_value" class="form-control"
                    aria-label="Value" value=(val) {}
            }
        }
        KeyType::Json => html! {
            input #add-value type="text" name="add_value" class="form-control"
                placeholder="{}" aria-label="Value"
                value=(current_value) {}
        },
        KeyType::String => html! {
            input #add-value type="text" name="add_value" class="form-control"
                placeholder="Value" aria-label="Value"
                value=(current_value) {}
        },
    }
}

/// Renders the description hint for a well-known key (if any), including a
/// type hint for Amount and DateTime fields whose unit labels are no longer
/// shown inline in the input-group.
fn render_value_description(key: &str) -> Markup {
    let schema = WELL_KNOWN_KEYS.get(key);
    let description = schema.map(|s| s.description).unwrap_or("");
    let type_hint = match schema.map(|s| &s.value_type) {
        Some(KeyType::DateTime) => " (UTC)",
        Some(KeyType::Amount) => " (msats)",
        _ => "",
    };

    html! {
        @if !description.is_empty() || !type_hint.is_empty() {
            small class="form-text text-muted" { (description) (type_hint) }
        }
    }
}

/// Renders a dropdown picker for well-known keys (plus any extra keys from
/// the current proposal). Picking a key copies it into the `#add-key` text
/// input and triggers its HTMX `change` event, then resets itself to "▾".
fn render_key_picker(extra_keys: &BTreeSet<String>) -> Markup {
    let all_keys: BTreeSet<&str> = WELL_KNOWN_KEYS
        .keys()
        .copied()
        .chain(extra_keys.iter().map(|s| s.as_str()))
        .collect();

    html! {
        select class="form-select"
            style="flex: 0 0 auto; width: 2em; padding-left: 0.2em;"
            aria-label="Pick a well-known key"
            onchange="if(this.value){var k=document.getElementById('add-key');k.value=this.value;this.value='';htmx.trigger(k,'change')}"
        {
            option value="" selected {}
            @for key in &all_keys {
                option value=(key) { (key) }
            }
        }
    }
}

/// Renders the Set button. When there is no Delete button next to it,
/// `rounded-end` is added so Bootstrap applies right border-radius despite
/// the hidden placeholder that follows.
fn render_set_button(key_in_proposal: bool, oob: bool) -> Markup {
    let class = if key_in_proposal {
        "btn btn-primary btn-min-width"
    } else {
        "btn btn-primary btn-min-width rounded-end"
    };
    html! {
        button #button-set class=(class) type="button"
            hx-swap-oob=[oob.then_some("outerHTML")]
            title="Set a value in a meta proposal"
            hx-post=(META_SET_ROUTE)
            hx-swap="none"
            hx-trigger="click, keypress[key=='Enter'] from:#add-value, keypress[key=='Enter'] from:#add-key"
        { "Set" }
    }
}

/// Renders the Delete button (visible) or a hidden placeholder (invisible).
/// Uses `outerHTML` OOB swap when returned from the HTMX endpoint.
fn render_delete_button(key: &str, visible: bool, oob: bool) -> Markup {
    if visible {
        html! {
            button #button-delete class="btn btn-danger btn-min-width" type="button"
                hx-swap-oob=[oob.then_some("outerHTML")]
                title="Delete this key from the proposal"
                hx-post=(META_DELETE_ROUTE)
                hx-swap="none"
                hx-vals=(format!(r#"{{"delete_key":"{}"}}"#, key))
            { "Delete" }
        }
    } else {
        html! {
            span #button-delete style="display:none"
                hx-swap-oob=[oob.then_some("outerHTML")]
            {}
        }
    }
}

/// Parses json_content into a JSON object map, returning empty map on failure.
fn parse_proposal(json_content: &str) -> serde_json::Map<String, Value> {
    serde_json::from_str(json_content)
        .ok()
        .and_then(|v: Value| v.as_object().cloned())
        .unwrap_or_default()
}

/// Query params for the value-input HTMX endpoint.
#[derive(serde::Deserialize)]
pub struct ValueInputQuery {
    #[serde(default)]
    pub add_key: String,
    #[serde(default)]
    pub json_content: String,
}

/// HTMX endpoint: returns a type-appropriate value input for the selected key
/// (primary `outerHTML` swap on `#add-value`), plus OOB swaps for the
/// description hint and the Set/Delete buttons.
pub async fn get_value_input(
    _auth: UserAuth,
    Query(query): Query<ValueInputQuery>,
) -> impl IntoResponse {
    let key = query.add_key.trim();
    let proposal = parse_proposal(&query.json_content);
    let key_in_proposal = !key.is_empty() && proposal.contains_key(key);

    let key_type = WELL_KNOWN_KEYS
        .get(key)
        .map(|s| &s.value_type)
        .unwrap_or(&KeyType::String);

    let content = html! {
        // Primary swap target: replaces #add-value via outerHTML
        (render_value_input(key_type, ""))
        // OOB swaps for description, Set button, and Delete button
        div #value-description-container hx-swap-oob="innerHTML" {
            (render_value_description(key))
        }
        (render_set_button(key_in_proposal, true))
        (render_delete_button(key, key_in_proposal, true))
    };
    Html(content.into_string())
}

/// Converts raw form input to a [`serde_json::Value`] appropriate for the
/// given key type.
fn convert_input_value(raw: &str, key_type: &KeyType) -> RequestResult<Value> {
    match key_type {
        KeyType::DateTime => {
            // Browsers may send with or without seconds
            let dt = CivilDateTime::strptime("%Y-%m-%dT%H:%M:%S", raw)
                .or_else(|_| CivilDateTime::strptime("%Y-%m-%dT%H:%M", raw))
                .map_err(|e| RequestError::BadRequest {
                    source: anyhow::anyhow!("Invalid datetime: {e}"),
                })?;
            let timestamp = dt
                .to_zoned_datetime(TimeZone::UTC)
                .map_err(|e| RequestError::BadRequest {
                    source: anyhow::anyhow!("Invalid datetime: {e}"),
                })?
                .timestamp();
            Ok(Value::String(timestamp.as_second().to_string()))
        }
        KeyType::Amount => {
            let _: u64 = raw.parse().map_err(|e| RequestError::BadRequest {
                source: anyhow::anyhow!("Invalid amount: {e}"),
            })?;
            Ok(Value::String(raw.to_string()))
        }
        KeyType::Json => serde_json::from_str(raw).map_err(|e| RequestError::BadRequest {
            source: anyhow::anyhow!("Invalid JSON: {e}"),
        }),
        KeyType::Url | KeyType::String => {
            // Try JSON parse first (backward compat), fall back to plain string
            Ok(serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string())))
        }
    }
}

pub fn render_meta_edit_form(
    consensus: &serde_json::Map<String, Value>,
    mut top_level_json: serde_json::Map<String, Value>,
    // was the value edited via set/delete
    pending: bool,
    form: MetaEditForm,
) -> Markup {
    top_level_json.sort_keys();

    let changes = compute_changes(consensus, &top_level_json);
    let extra_keys: BTreeSet<String> = top_level_json.keys().cloned().collect();
    let all_keys: BTreeSet<&str> = WELL_KNOWN_KEYS
        .keys()
        .copied()
        .chain(extra_keys.iter().map(|s| s.as_str()))
        .collect();
    let default_input = render_value_input(&KeyType::String, &form.add_value);

    html! {
        form #meta-edit-form hx-swap-oob=(true) {
            h5 {
                "Propose Changes"
                @if pending {
                    " (Pending - click Submit to Propose)"
                }
            }
            input type="hidden" name="json_content"
                value=(serde_json::to_string_pretty(&top_level_json).expect("Can't fail")) {}
            div class="row mb-2" {
                div class="col-md-6" {
                    strong { "Full proposal" }
                    pre class="m-0 p-2 bg-light" style="min-height: 120px; max-height: 40vh; overflow-y: auto;" {
                        code {
                            (serde_json::to_string_pretty(&top_level_json).expect("Can't fail"))
                        }
                    }
                }
                div class="col-md-6" {
                    (render_changes_summary(&changes))
                }
            }
            // Datalist for autocomplete on the key text input
            datalist #keyOptions {
                @for key in &all_keys {
                    option value=(key) {}
                }
            }
            // All children are direct elements — no wrapper divs — so
            // Bootstrap's input-group :first-child/:last-child CSS works.
            div class="input-group mb-1" {
                (render_key_picker(&extra_keys))
                input #add-key type="text" list="keyOptions" name="add_key" class="form-control"
                    style="max-width: 250px;" placeholder="Key"
                    hx-get=(META_VALUE_INPUT_ROUTE)
                    hx-trigger="change, input changed delay:300ms"
                    hx-target="#add-value"
                    hx-swap="outerHTML"
                    hx-include="#meta-edit-form [name='json_content']"
                {}
                span class="input-group-text" { ":" }
                (default_input)
                (render_set_button(false, false))
                (render_delete_button("", false, false))
            }
            div #value-description-container {}
            div class="d-flex justify-content-between btn-min-width" {
                button type="button" class="btn btn-outline-warning me-5"
                    title="Reset to current consensus"
                    hx-post=(META_RESET_ROUTE)
                    hx-swap="none"
                    hx-confirm="This will clear all the changes in your proposal. Are you sure?"
                { "Reset" }
                button type="button" class="btn btn-success btn-min-width"
                    hx-post=(META_SUBMIT_ROUTE)
                    hx-swap="none"
                    title="Submit new meta document for approval of other peers"
                { "Submit" }
            }
        }
    }
}

/// Wrapper over `T` to make it a json request response
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(RequestError))]
struct AppJson<T>(pub T);

impl<T> IntoResponse for AppJson<T>
where
    axum::Json<T>: IntoResponse,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// Whatever can go wrong with a request
#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Bad request: {source}")]
    BadRequest { source: anyhow::Error },
    #[error("Internal Error")]
    InternalError,
}

pub type RequestResult<T> = std::result::Result<T, RequestError>;

impl IntoResponse for RequestError {
    fn into_response(self) -> Response {
        debug!(target: LOG_UI, err=%self, "Request Error");

        let (status_code, message) = match self {
            Self::BadRequest { source } => {
                (StatusCode::BAD_REQUEST, format!("Bad Request: {source}"))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Service Error".to_owned(),
            ),
        };

        (status_code, AppJson(UserErrorResponse { message })).into_response()
    }
}

// How we want user errors responses to be serialized
#[derive(Serialize)]
pub struct UserErrorResponse {
    pub message: String,
}
