use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use fedimint_core::PeerId;
use fedimint_core::module::serde_json::{self, Value};
use fedimint_meta_server::Meta;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use maud::{Markup, html};
use tracing::warn;

use crate::error::{RequestError, RequestResult};
use crate::{AuthState, LOG_UI, check_auth};

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
                    @if let Some(value) = &consensus_value {
                        pre class="bg-light p-3 user-select-all" {
                            code {
                                (serde_json::to_string_pretty(value).unwrap_or_else(|_| "Invalid JSON".to_string()))
                            }
                        }
                    } @else {
                        div class="alert alert-secondary" { "No consensus value has been established yet." }
                    }
                    div class="mb-4" {
                        (render_meta_edit_form(current_meta_keys, false, MetaEditForm::default()))
                    }

                    (render_submissions_form(meta.our_peer_id, &submissions))
                }
            }
        }
    }
}

fn render_submissions_form(our_id: PeerId, submissions: &BTreeMap<PeerId, Value>) -> Markup {
    let mut submissions_by_value: HashMap<String, BTreeSet<PeerId>> = HashMap::new();

    for (peer_id, value) in submissions {
        let value_str =
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "Invalid JSON".to_string());
        submissions_by_value
            .entry(value_str)
            .or_default()
            .insert(*peer_id);
    }

    html! {
        div #meta-submissions hx-swap-oob=(true) {
            @if !submissions.is_empty() {
                h5 { "Current Peer Submissions" }
                div class="table-responsive" {
                    table class="table table-sm" {
                        thead {
                            tr {
                                th { "Peer IDs" }
                                th { "Submission" }
                                th { "Actions" }
                            }
                        }
                        tbody {
                            @for (value_str, peer_ids) in submissions_by_value {
                                tr {
                                    td { (
                                        peer_ids.iter()
                                        .map(|n| n.to_string())
                                        .collect::<Vec<String>>()
                                        .join(", "))
                                    }
                                    td {
                                        pre class="m-0 p-2 bg-light" style="max-height: 150px; overflow-y: auto;" {
                                            code {
                                                (value_str)
                                            }
                                        }
                                    }
                                    @if !peer_ids.contains(&our_id) {
                                        td {
                                            form method="post"
                                                hx-post="/meta/submit"
                                                hx-swap="none"
                                            {
                                                input type="hidden" name="json_content"
                                                    value=(value_str);
                                                button type="submit" class="btn btn-sm btn-success" {
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

pub async fn post_submit(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(form): Form<MetaEditForm>,
) -> RequestResult<Response> {
    // Check authentication
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Ok(Redirect::to("/login").into_response());
    }

    let meta_module = state.api.get_module::<Meta>().unwrap();

    let top_level_keys = form.top_level_keys()?;
    let top_level_object = Value::Object(top_level_keys.clone());

    meta_module
        .handle_submit_request_ui(top_level_object.clone())
        .await
        .inspect_err(|msg| warn!(target: LOG_UI, msg= %msg.message, "Request error"))
        .map_err(|_err| RequestError::InternalError)?;

    let mut submissions = meta_module
        .handle_get_submissions_request_ui()
        .await
        .ok()
        .unwrap_or_default();

    submissions.insert(meta_module.our_peer_id, top_level_object);

    let content = html! {
        (render_meta_edit_form(top_level_keys, false, MetaEditForm::default()))

        // Re-render submission with our submission added, as it will take couple of milliseconds
        // for it to get processed and it's confusing if it doesn't immediatel show up.
        (render_submissions_form(meta_module.our_peer_id, &submissions))
    };
    Ok(Html(content.into_string()).into_response())
}

pub async fn post_reset(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(_form): Form<MetaEditForm>,
) -> RequestResult<Response> {
    // Check authentication
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Ok(Redirect::to("/login").into_response());
    }

    let meta_module = state.api.get_module::<Meta>().unwrap();

    let consensus_value = meta_module
        .handle_get_consensus_request_ui()
        .await
        .ok()
        .flatten();

    let top_level_keys = if let Some(serde_json::Value::Object(o)) = consensus_value {
        o
    } else {
        serde_json::Map::new()
    };
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
        (render_meta_edit_form(top_level_keys, false, MetaEditForm::default()))

        // Re-render submission with our submission added, as it will take couple of milliseconds
        // for it to get processed and it's confusing if it doesn't immediatel show up.
        (render_submissions_form(meta_module.our_peer_id, &submissions))
    };
    Ok(Html(content.into_string()).into_response())
}

pub async fn post_set(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(mut form): Form<MetaEditForm>,
) -> RequestResult<Response> {
    // Check authentication
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Ok(Redirect::to("/login").into_response());
    }

    let mut top_level_object = form.top_level_keys()?;

    let key = form.add_key.trim();
    let value = form.add_value.trim();
    let value = serde_json::from_str(value)
        .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));

    top_level_object.insert(key.to_string(), value);

    form.add_key = "".into();
    form.add_value = "".into();
    let content = render_meta_edit_form(top_level_object, true, MetaEditForm::default());
    Ok(Html(content.into_string()).into_response())
}

pub async fn post_delete(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(mut form): Form<MetaEditForm>,
) -> RequestResult<Response> {
    // Check authentication
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Ok(Redirect::to("/login").into_response());
    }

    let mut top_level_json = form.top_level_keys()?;

    let key = form.delete_key.trim();

    top_level_json.remove(key);
    form.delete_key = "".into();

    let content = render_meta_edit_form(top_level_json, true, form);
    Ok(Html(content.into_string()).into_response())
}

// <https://fedibtc.github.io/fedi-docs/docs/fedi/meta_fields/federation-metadata-configurations>
const WELL_KNOWN_KEYS: &[&str] = &[
    "welcome_message",
    "fedi:pinned_message",
    "fedi:federation_icon_url",
    "fedi:tos_url",
    "fedi:default_currency",
    "fedi:popup_end_timestamp",
    "fedi:invite_codes_disabled",
    "fedi:new_members_disabled",
    "fedi:max_invoice_msats",
    "fedi:max_balance_msats",
    "fedi:max_stable_balance_msats",
    "fedi:fedimods",
    "fedi:default_group_chats",
    "fedi:offline_wallet_disabled",
];

pub fn render_meta_edit_form(
    mut top_level_json: serde_json::Map<String, Value>,
    // was the value edited via set/delete
    pending: bool,
    form: MetaEditForm,
) -> Markup {
    top_level_json.sort_keys();

    let known_keys: HashSet<String> = top_level_json
        .keys()
        .cloned()
        .chain(WELL_KNOWN_KEYS.iter().map(ToString::to_string))
        .collect();
    html! {
        form #meta-edit-form hx-swap-oob=(true) {
            h5 {
                "Proposal"
                @if pending {
                    " (Pending)"
                }
            }
            div class="input-group mb-2" {
                textarea class="form-control" rows="15" readonly
                    name="json_content"
                {
                    (serde_json::to_string_pretty(&top_level_json).expect("Can't fail"))
                }
            }
            div class="input-group mb-2" {
                input #add-key  type="text" class="form-control" placeholder="Key" aria-label="Key" list="keyOptions"
                    // keys are usually shorter than values, so keep it small
                    style="max-width: 250px;"
                    name="add_key"
                    value=(form.add_key)
                {}
                span class="input-group-text" { ":" }
                input #add-value type="text" name="add_value" class="form-control" placeholder="Value" aria-label="Value"
                    value=(form.add_value)
                {}

                datalist id="keyOptions" {
                    @for key in known_keys {
                        option value=(key) {}
                    }
                }

                button class="btn btn-primary btn-min-width"
                    type="button" id="button-set"
                    title="Set a value in a meta proposal"
                    hx-post="/meta/set"
                    hx-swap="none"
                    hx-trigger="click, keypress[key=='Enter'] from:#add-value, keypress[key=='Enter'] from:#add-key"
                { "Set" }
            }
            div class="input-group mb-2" {
                select class="form-select"
                    id="delete-key"
                    name="delete_key"
                {
                    option value="" {}
                    @for key in top_level_json.keys() {
                        option value=(key) selected[key == &form.delete_key]{ (key) }
                    }
                }
                button class="btn btn-primary btn-min-width"
                    hx-post="/meta/delete"
                    hx-swap="none"
                    hx-trigger="click, keypress[key=='Enter'] from:#delete-key"
                    title="Delete a value in a meta proposal"
                { "Delete" }
            }
            div class="d-flex justify-content-between btn-min-width" {
                button class="btn btn-outline-warning me-5"
                    title="Reset to current consensus"
                    hx-post="/meta/reset"
                    hx-swap="none"
                { "Reset" }
                button class="btn btn-success btn-min-width"
                    hx-post="/meta/submit"
                    hx-swap="none"
                    title="Submit new meta document for approval of other peers"
                { "Submit" }
            }
        }
    }
}
