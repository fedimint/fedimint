use std::collections::BTreeSet;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use fedimint_core::core::ModuleKind;
use fedimint_core::module::ApiAuth;
use fedimint_server_core::setup_ui::DynSetupApi;
use fedimint_ui_common::assets::WithStaticRoutesExt;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{
    CONNECTIVITY_CHECK_ROUTE, LOGIN_ROUTE, LoginInput, ROOT_ROUTE, UiState,
    connectivity_check_handler, copiable_text, login_form, login_submit_response,
    single_card_layout, single_card_layout_with_version,
};
use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;
use serde::Deserialize;

// Setup route constants
pub const FEDERATION_SETUP_ROUTE: &str = "/federation_setup";
pub const ADD_SETUP_CODE_ROUTE: &str = "/add_setup_code";
pub const RESET_SETUP_CODES_ROUTE: &str = "/reset_setup_codes";
pub const START_DKG_ROUTE: &str = "/start_dkg";
pub const START_FEDERATION_ROUTE: &str = "/start_federation";
pub const RESTORE_GUARDIAN_ROUTE: &str = "/restore_guardian";
const RESTORE_BACKUP_UPLOAD_LIMIT_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub(crate) struct SetupInput {
    pub password: String,
    pub name: String,
    #[serde(default)]
    pub is_lead: bool,
    pub federation_name: String,
    #[serde(default)]
    pub federation_size: String,
    #[serde(default)] // will not be sent if disabled
    pub enable_base_fees: bool,
    #[serde(default)] // list of enabled module kinds
    pub enabled_modules: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PeerInfoInput {
    pub peer_info: String,
}

fn peer_list_section(
    connected_peers: &[String],
    federation_size: Option<u32>,
    cfg_federation_name: &Option<String>,
    cfg_base_fees_disabled: Option<bool>,
    cfg_enabled_modules: &Option<BTreeSet<ModuleKind>>,
    error: Option<&str>,
) -> Markup {
    let total_guardians = connected_peers.len() + 1;
    let can_start_dkg = federation_size
        .map(|expected| total_guardians == expected as usize)
        .unwrap_or(false);

    html! {
        div id="peer-list-section" {
            @if let Some(expected) = federation_size {
                p { (format!("{total_guardians} of {expected} guardians connected.")) }
            } @else {
                p { "Add setup code for every other guardian." }
            }

            @if !connected_peers.is_empty() {
                ul class="list-group mb-2" {
                    @for peer in connected_peers {
                        li class="list-group-item" { (peer) }
                    }
                }

                form id="reset-form" method="post" action=(RESET_SETUP_CODES_ROUTE) class="d-none" {}
                div class="text-center mb-4" {
                    button type="button" class="btn btn-link text-danger text-decoration-none p-0" onclick="if(confirm('Are you sure you want to reset all guardians?')){document.getElementById('reset-form').submit();}" {
                        "Reset Guardians"
                    }
                }
            }

            @if can_start_dkg {
                // All guardians connected — show confirm form
                @let has_settings = cfg_federation_name.is_some()
                    || federation_size.is_some()
                    || cfg_base_fees_disabled.is_some()
                    || cfg_enabled_modules.is_some();

                form id="start-dkg-form" hx-post=(START_DKG_ROUTE) hx-target="#peer-list-section" hx-swap="outerHTML" {
                    @if let Some(error) = error {
                        div class="alert alert-danger mb-3" { (error) }
                    }
                    button type="submit" class="btn btn-warning w-100 py-2" { "Confirm" }
                }

                @if has_settings {
                    p class="text-muted mt-3 mb-0" style="font-size: 0.85rem;" {
                        @if let Some(name) = cfg_federation_name {
                            (name) " federation has been configured"
                        } @else {
                            "The federation has been configured"
                        }
                        @if let Some(disabled) = cfg_base_fees_disabled {
                            " with base fees "
                            @if disabled { "disabled" } @else { "enabled" }
                        }
                        @if let Some(modules) = cfg_enabled_modules {
                            " and modules "
                            (modules.iter().map(|m| m.as_str().to_owned()).collect::<Vec<_>>().join(", "))
                        }
                        "."
                    }
                }
            } @else {
                // Still collecting — show add guardian form
                form id="add-setup-code-form" hx-post=(ADD_SETUP_CODE_ROUTE) hx-target="#peer-list-section" hx-swap="outerHTML" {
                    div class="mb-3" {
                        div class="input-group" {
                            input type="text" class="form-control" id="peer_info" name="peer_info"
                                placeholder="Paste Setup Code" required;
                            button type="button" class="btn btn-outline-secondary" onclick="startQrScanner()" title="Scan QR Code" {
                                i class="bi bi-qr-code-scan" {}
                            }
                        }
                    }

                    @if let Some(error) = error {
                        div class="alert alert-danger mb-3" { (error) }
                    }
                    button type="submit" class="btn btn-primary w-100 py-2" { "Add Guardian" }
                }
            }
        }
    }
}

fn setup_error_message(error: &str) -> Markup {
    html! {
        div class="alert alert-danger mb-3" { (error) }
    }
}

fn setup_choice_content(error: Option<&str>) -> Markup {
    html! {
        @if let Some(error) = error {
            (setup_error_message(error))
        }

        div class="d-grid gap-3" {
            a href=(START_FEDERATION_ROUTE) class="btn btn-primary w-100 py-2" {
                "Start new Federation"
            }

            a href=(RESTORE_GUARDIAN_ROUTE) class="btn btn-outline-secondary w-100 py-2" {
                "Restore from backup"
            }
        }
    }
}

fn restore_form_content(error: Option<&str>) -> Markup {
    html! {
        @if let Some(error) = error {
            (setup_error_message(error))
        }

        p class="text-muted" {
            "Upload a guardian backup tar file and enter the guardian password used when the backup was created."
        }

        form method="post" action=(RESTORE_GUARDIAN_ROUTE) enctype="multipart/form-data" {
            div class="form-group mb-3" {
                input type="password" class="form-control" name="password" placeholder="Guardian Password" required;
            }
            div class="form-group mb-3" {
                input type="file" class="form-control" name="backup" accept="application/x-tar,.tar" required;
            }
            button type="submit" class="btn btn-primary w-100 py-2" {
                "Restore Guardian"
            }
        }

        div class="text-center mt-3" {
            a href=(ROOT_ROUTE) class="btn btn-link text-muted text-decoration-none" {
                "Back"
            }
        }
    }
}

fn restore_error_response(error: impl AsRef<str>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Html(
            single_card_layout(
                "Restore Guardian",
                restore_form_content(Some(error.as_ref())),
            )
            .into_string(),
        ),
    )
        .into_response()
}

fn setup_form_content(
    available_modules: &BTreeSet<ModuleKind>,
    default_modules: &BTreeSet<ModuleKind>,
) -> Markup {
    html! {
        form id="setup-form" hx-post=(ROOT_ROUTE) hx-target="#setup-error" hx-swap="innerHTML" {
            style {
                r#"
                .toggle-content {
                    display: none;
                }

                .toggle-control:checked ~ .toggle-content {
                    display: block;
                }

                #base-fees-warning {
                    display: block;
                }

                .form-check:has(#enable_base_fees:checked) + #base-fees-warning {
                    display: none;
                }

                .accordion-button {
                    background-color: #f8f9fa;
                }

                .accordion-button:not(.collapsed) {
                    background-color: #f8f9fa;
                    box-shadow: none;
                }

                .accordion-button:focus {
                    box-shadow: none;
                }

                #modules-warning {
                    display: none;
                }

                #modules-list:has(.form-check-input:not(:checked)) ~ #modules-warning {
                    display: block;
                }
                "#
            }

            div class="form-group mb-4" {
                input type="text" class="form-control" id="name" name="name" placeholder="Your Guardian Name" required;
            }

            div class="form-group mb-4" {
                input type="password" class="form-control" id="password" name="password" placeholder="Your Password" required;
            }

            div class="alert alert-warning mb-3" style="font-size: 0.875rem;" {
                "Exactly one guardian must set the global config."
            }

            div class="form-group mb-4" {
                input type="checkbox" class="form-check-input toggle-control" id="is_lead" name="is_lead" value="true";

                label class="form-check-label ms-2" for="is_lead" {
                    "Set the global config"
                }

                div class="toggle-content mt-3" {
                    input type="text" class="form-control" id="federation_name" name="federation_name" placeholder="Federation Name";

                    div class="form-group mt-3" {
                        label class="form-label" for="federation_size" {
                            "Total number of guardians (including you)"
                        }
                        select class="form-select" id="federation_size" name="federation_size" {
                            option value="" selected disabled { "Federation Size" }
                            option value="1" { "1 — Testing" }
                            option value="4" { "4 — Recommended" }
                            option value="5" { "5" }
                            option value="6" { "6" }
                            option value="7" { "7 — Recommended" }
                            option value="8" { "8" }
                            option value="9" { "9" }
                            option value="10" { "10 — Recommended" }
                            option value="11" { "11" }
                            option value="12" { "12" }
                            option value="13" { "13 — Recommended" }
                            option value="14" { "14" }
                            option value="15" { "15" }
                            option value="16" { "16 — Recommended" }
                            option value="17" { "17" }
                            option value="18" { "18" }
                            option value="19" { "19 — Recommended" }
                            option value="20" { "20" }
                        }
                    }

                    div class="form-check mt-3" {
                        input type="checkbox" class="form-check-input" id="enable_base_fees" name="enable_base_fees" checked value="true";

                        label class="form-check-label" for="enable_base_fees" {
                            "Enable base fees for this federation"
                        }
                    }

                    div id="base-fees-warning" class="alert alert-warning mt-2" style="font-size: 0.875rem;" {
                        strong { "Warning: " }
                        "Base fees discourage spam and wasting storage space. The typical fee is only 1-3 sats per transaction, regardless of the value transferred. We recommend enabling the base fee and it cannot be changed later."
                    }

                    div class="accordion mt-3" id="modulesAccordion" {
                        div class="accordion-item" {
                            h2 class="accordion-header" {
                                button class="accordion-button collapsed" type="button"
                                    data-bs-toggle="collapse" data-bs-target="#modulesConfig"
                                    aria-expanded="false" aria-controls="modulesConfig" {
                                    "Advanced: Configure Enabled Modules"
                                }
                            }
                            div id="modulesConfig" class="accordion-collapse collapse" data-bs-parent="#modulesAccordion" {
                                div class="accordion-body" {
                                    div id="modules-list" {
                                        @for kind in available_modules {
                                            div class="form-check" {
                                                input type="checkbox" class="form-check-input"
                                                    id=(format!("module_{}", kind.as_str()))
                                                    name="enabled_modules"
                                                    value=(kind.as_str())
                                                    checked[default_modules.contains(kind)];

                                                label class="form-check-label" for=(format!("module_{}", kind.as_str())) {
                                                    (kind.as_str())
                                                    @if !default_modules.contains(kind) {
                                                        span class="badge bg-warning text-dark ms-2" { "experimental" }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    div id="modules-warning" class="alert alert-warning mt-2 mb-0" style="font-size: 0.875rem;" {
                                        "Only modify this if you know what you are doing. Disabled modules cannot be enabled later."
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div id="setup-error" {}
            button type="submit" class="btn btn-primary w-100 py-2" { "Confirm" }
        }
    }
}

// GET handler for the / route (choose setup or restore)
async fn setup_form(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_some() {
        return Redirect::to(FEDERATION_SETUP_ROUTE).into_response();
    }

    Html(single_card_layout("Guardian Setup", setup_choice_content(None)).into_string())
        .into_response()
}

// GET handler for starting a new federation
async fn start_federation_form(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_some() {
        return Redirect::to(FEDERATION_SETUP_ROUTE).into_response();
    }

    let available_modules = state.api.available_modules();
    let default_modules = state.api.default_modules();
    let content = setup_form_content(&available_modules, &default_modules);
    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;

    Html(
        single_card_layout_with_version(
            "Guardian Setup",
            content,
            &version,
            version_hash.as_deref(),
        )
        .into_string(),
    )
    .into_response()
}

// POST handler for the /setup route (process the setup form)
async fn setup_submit(
    State(state): State<UiState<DynSetupApi>>,
    Form(input): Form<SetupInput>,
) -> impl IntoResponse {
    // Only use these settings if is_lead is true
    let federation_name = if input.is_lead {
        Some(input.federation_name)
    } else {
        None
    };

    let disable_base_fees = if input.is_lead {
        Some(!input.enable_base_fees)
    } else {
        None
    };

    let enabled_modules = if input.is_lead {
        let enabled: BTreeSet<ModuleKind> = input
            .enabled_modules
            .into_iter()
            .map(|s| ModuleKind::clone_from_str(&s))
            .collect();

        Some(enabled)
    } else {
        None
    };

    let federation_size = if input.is_lead {
        let s = input.federation_size.trim();
        if s.is_empty() {
            None
        } else {
            match s.parse::<u32>() {
                Ok(size) => Some(size),
                Err(_) => {
                    return Html(setup_error_message("Invalid federation size").into_string())
                        .into_response();
                }
            }
        }
    } else {
        None
    };

    match state
        .api
        .set_local_parameters(
            ApiAuth::new(input.password),
            input.name,
            federation_name,
            disable_base_fees,
            enabled_modules,
            federation_size,
        )
        .await
    {
        Ok(_) => (
            [("HX-Redirect", FEDERATION_SETUP_ROUTE)],
            Html(String::new()),
        )
            .into_response(),
        Err(e) => Html(setup_error_message(&e.to_string()).into_string()).into_response(),
    }
}

// GET handler for restoring from backup
async fn restore_form(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_some() {
        return Redirect::to(FEDERATION_SETUP_ROUTE).into_response();
    }

    Html(single_card_layout("Restore Guardian", restore_form_content(None)).into_string())
        .into_response()
}

async fn restore_submit(
    State(state): State<UiState<DynSetupApi>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut password = None;
    let mut backup = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(e) => return restore_error_response(format!("Failed to read upload: {e}")),
        };

        match field.name() {
            Some("password") => match field.text().await {
                Ok(value) => password = Some(value),
                Err(e) => return restore_error_response(format!("Failed to read password: {e}")),
            },
            Some("backup") => match field.bytes().await {
                // The setup UI is a local guardian-owner interface. We cap the upload size to
                // catch accidental oversized requests, but treat malicious tar expansion by the
                // uploading user as out of scope: they already control this guardian instance.
                Ok(value) => backup = Some(value.to_vec()),
                Err(e) => return restore_error_response(format!("Failed to read backup: {e}")),
            },
            _ => {}
        }
    }

    let Some(password) = password else {
        return restore_error_response("Missing guardian password");
    };
    let Some(backup) = backup else {
        return restore_error_response("Missing guardian backup file");
    };

    match state.api.restore_from_backup(password, backup).await {
        Ok(()) => {
            let content = html! {
                div class="alert alert-success mb-3" {
                    "Guardian backup restored. The server is starting consensus."
                }
                div class="text-center mt-4" {
                    div class="spinner-border text-primary" role="status" {
                        span class="visually-hidden" { "Loading..." }
                    }
                    p class="mt-2 text-muted" { "Waiting for dashboard..." }
                }
                div
                    hx-get=(ROOT_ROUTE)
                    hx-trigger="every 2s"
                    hx-swap="none"
                    hx-on--after-request={
                        "if (event.detail.xhr.status === 200) { window.location.href = '" (ROOT_ROUTE) "'; }"
                    }
                    style="display: none;"
                {}
            };
            Html(single_card_layout("Guardian Restored", content).into_string()).into_response()
        }
        Err(e) => restore_error_response(e.to_string()),
    }
}

// GET handler for the /login route (display the login form)
async fn login_form_handler(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_none() {
        return Redirect::to(ROOT_ROUTE).into_response();
    }

    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;
    Html(
        single_card_layout_with_version(
            "Enter Password",
            login_form(None),
            &version,
            version_hash.as_deref(),
        )
        .into_string(),
    )
    .into_response()
}

// POST handler for the /login route (authenticate and set session cookie)
async fn login_submit(
    State(state): State<UiState<DynSetupApi>>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    let auth = match state.api.auth().await {
        Some(auth) => auth,
        None => return Redirect::to(ROOT_ROUTE).into_response(),
    };

    login_submit_response(
        auth,
        state.auth_cookie_name,
        state.auth_cookie_value,
        jar,
        input,
    )
    .into_response()
}

// GET handler for the /federation-setup route (main federation management page)
async fn federation_setup(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    let our_connection_info = state
        .api
        .setup_code()
        .await
        .expect("Successful authentication ensures that the local parameters have been set");

    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;
    let connected_peers = state.api.connected_peers().await;
    let federation_size = state.api.federation_size().await;
    let cfg_federation_name = state.api.cfg_federation_name().await;
    let cfg_base_fees_disabled = state.api.cfg_base_fees_disabled().await;
    let cfg_enabled_modules = state.api.cfg_enabled_modules().await;

    let content = html! {
        p { "Share this with your fellow guardians." }

        @let qr_svg = QrCode::new(&our_connection_info)
            .expect("Failed to generate QR code")
            .render::<qrcode::render::svg::Color>()
            .build();

        div class="text-center mb-3" {
            div class="border rounded p-2 bg-white d-inline-block" style="width: 250px; max-width: 100%;" {
                div style="width: 100%; height: auto; overflow: hidden;" {
                    (PreEscaped(format!(r#"<div style="width: 100%; height: auto;">{}</div>"#,
                        qr_svg.replace("width=", "data-width=")
                              .replace("height=", "data-height=")
                              .replace("<svg", r#"<svg style="width: 100%; height: auto; display: block;""#))))
                }
            }
        }

        div class="mb-4" {
            (copiable_text(&our_connection_info))
        }

        (peer_list_section(&connected_peers, federation_size, &cfg_federation_name, cfg_base_fees_disabled, &cfg_enabled_modules, None))

        // QR Scanner Modal
        div class="modal fade" id="qrScannerModal" tabindex="-1" aria-labelledby="qrScannerModalLabel" aria-hidden="true" {
            div class="modal-dialog modal-dialog-centered" {
                div class="modal-content" {
                    div class="modal-header" {
                        h5 class="modal-title" id="qrScannerModalLabel" { "Scan Setup Code" }
                        button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close" {}
                    }
                    div class="modal-body" {
                        div id="qr-reader" style="width: 100%;" {}
                        div id="qr-reader-error" class="alert alert-danger mt-3 d-none" {}
                    }
                    div class="modal-footer" {
                        button type="button" class="btn btn-secondary" data-bs-dismiss="modal" { "Cancel" }
                    }
                }
            }
        }

        script src="/assets/html5-qrcode.min.js" {}

        // QR Scanner JavaScript
        script {
            (PreEscaped(r#"
            var html5QrCode = null;
            var qrScannerModal = null;

            function startQrScanner() {
                // Check for Flutter override hook
                if (typeof window.fedimintQrScannerOverride === 'function') {
                    window.fedimintQrScannerOverride(function(result) {
                        if (result) {
                            document.getElementById('peer_info').value = result;
                        }
                    });
                    return;
                }

                var modalEl = document.getElementById('qrScannerModal');
                qrScannerModal = new bootstrap.Modal(modalEl);

                // Reset error message
                var errorEl = document.getElementById('qr-reader-error');
                errorEl.classList.add('d-none');
                errorEl.textContent = '';

                qrScannerModal.show();

                // Wait for modal to be shown before starting camera
                modalEl.addEventListener('shown.bs.modal', function onShown() {
                    modalEl.removeEventListener('shown.bs.modal', onShown);
                    initializeScanner();
                });

                // Clean up when modal is hidden
                modalEl.addEventListener('hidden.bs.modal', function onHidden() {
                    modalEl.removeEventListener('hidden.bs.modal', onHidden);
                    stopQrScanner();
                });
            }

            function initializeScanner() {
                html5QrCode = new Html5Qrcode("qr-reader");

                var config = {
                    fps: 10,
                    qrbox: { width: 250, height: 250 },
                    aspectRatio: 1.0
                };

                html5QrCode.start(
                    { facingMode: "environment" },
                    config,
                    function(decodedText, decodedResult) {
                        // Success - populate input and close modal
                        document.getElementById('peer_info').value = decodedText;
                        qrScannerModal.hide();
                    },
                    function(errorMessage) {
                        // Ignore scan errors (happens constantly while searching)
                    }
                ).catch(function(err) {
                    var errorEl = document.getElementById('qr-reader-error');
                    errorEl.textContent = 'Unable to access camera: ' + err;
                    errorEl.classList.remove('d-none');
                });
            }

            function stopQrScanner() {
                if (html5QrCode && html5QrCode.isScanning) {
                    html5QrCode.stop().catch(function(err) {
                        console.error('Error stopping scanner:', err);
                    });
                }
            }
            "#))
        }
    };

    Html(
        single_card_layout_with_version(
            "Federation Setup",
            content,
            &version,
            version_hash.as_deref(),
        )
        .into_string(),
    )
    .into_response()
}

// POST handler for adding peer connection info
async fn post_add_setup_code(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
    Form(input): Form<PeerInfoInput>,
) -> impl IntoResponse {
    let error = state.api.add_peer_setup_code(input.peer_info).await.err();

    let connected_peers = state.api.connected_peers().await;
    let federation_size = state.api.federation_size().await;
    let cfg_federation_name = state.api.cfg_federation_name().await;
    let cfg_base_fees_disabled = state.api.cfg_base_fees_disabled().await;
    let cfg_enabled_modules = state.api.cfg_enabled_modules().await;

    Html(
        peer_list_section(
            &connected_peers,
            federation_size,
            &cfg_federation_name,
            cfg_base_fees_disabled,
            &cfg_enabled_modules,
            error.as_ref().map(|e| e.to_string()).as_deref(),
        )
        .into_string(),
    )
    .into_response()
}

// POST handler for starting the DKG process
async fn post_start_dkg(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    let our_connection_info = state.api.setup_code().await;
    let version = state.api.fedimintd_version().await;
    let version_hash = state.api.fedimintd_version_hash().await;

    match state.api.start_dkg().await {
        Ok(()) => {
            let content = html! {
                @if let Some(ref info) = our_connection_info {
                    p { "Share with guardians who still need it." }
                    div class="mb-4" {
                        (copiable_text(info))
                    }
                }

                div class="alert alert-info mb-3" {
                    "All guardians need to confirm their settings. Once completed you will be redirected to the Dashboard."
                }

                // Poll until the dashboard is ready, then redirect
                div
                    hx-get=(ROOT_ROUTE)
                    hx-trigger="every 2s"
                    hx-swap="none"
                    hx-on--after-request={
                        "if (event.detail.xhr.status === 200) { window.location.href = '" (ROOT_ROUTE) "'; }"
                    }
                    style="display: none;"
                {}

                div class="text-center mt-4" {
                    div class="spinner-border text-primary" role="status" {
                        span class="visually-hidden" { "Loading..." }
                    }
                    p class="mt-2 text-muted" { "Waiting for federation setup to complete..." }
                }
            };

            (
                [("HX-Retarget", "body"), ("HX-Reswap", "innerHTML")],
                Html(
                    single_card_layout_with_version(
                        "DKG Started",
                        content,
                        &version,
                        version_hash.as_deref(),
                    )
                    .into_string(),
                ),
            )
                .into_response()
        }
        Err(e) => {
            let connected_peers = state.api.connected_peers().await;
            let federation_size = state.api.federation_size().await;
            let cfg_federation_name = state.api.cfg_federation_name().await;
            let cfg_base_fees_disabled = state.api.cfg_base_fees_disabled().await;
            let cfg_enabled_modules = state.api.cfg_enabled_modules().await;

            Html(
                peer_list_section(
                    &connected_peers,
                    federation_size,
                    &cfg_federation_name,
                    cfg_base_fees_disabled,
                    &cfg_enabled_modules,
                    Some(&e.to_string()),
                )
                .into_string(),
            )
            .into_response()
        }
    }
}

// POST handler for resetting peer connection info
async fn post_reset_setup_codes(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    state.api.reset_setup_codes().await;

    Redirect::to(FEDERATION_SETUP_ROUTE).into_response()
}

pub fn router(api: DynSetupApi) -> Router {
    Router::new()
        .route(ROOT_ROUTE, get(setup_form).post(setup_submit))
        .route(START_FEDERATION_ROUTE, get(start_federation_form))
        .route(
            RESTORE_GUARDIAN_ROUTE,
            get(restore_form)
                .post(restore_submit)
                .layer(DefaultBodyLimit::max(RESTORE_BACKUP_UPLOAD_LIMIT_BYTES)),
        )
        .route(LOGIN_ROUTE, get(login_form_handler).post(login_submit))
        .route(FEDERATION_SETUP_ROUTE, get(federation_setup))
        .route(ADD_SETUP_CODE_ROUTE, post(post_add_setup_code))
        .route(RESET_SETUP_CODES_ROUTE, post(post_reset_setup_codes))
        .route(START_DKG_ROUTE, post(post_start_dkg))
        .route(
            CONNECTIVITY_CHECK_ROUTE,
            get(connectivity_check_handler::<DynSetupApi>),
        )
        .with_static_routes()
        .with_state(UiState::new(api))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_form_targets_error_container() {
        let content = setup_form_content(&BTreeSet::new(), &BTreeSet::new()).into_string();

        assert!(content.contains(r##"hx-target="#setup-error""##));
        assert!(content.contains(r#"<div id="setup-error"></div>"#));
    }

    #[test]
    fn setup_error_message_is_partial() {
        let content = setup_error_message("Invalid federation size").into_string();

        assert!(content.contains("Invalid federation size"));
        assert!(!content.contains("setup-form"));
    }

    #[test]
    fn setup_choice_has_start_and_restore_options() {
        let content = setup_choice_content(None).into_string();

        assert!(content.contains("Start new Federation"));
        assert!(content.contains("Restore from backup"));
        assert!(!content.contains("multipart/form-data"));
    }

    #[test]
    fn restore_form_has_upload_fields() {
        let content = restore_form_content(None).into_string();

        assert!(content.contains("multipart/form-data"));
        assert!(content.contains("Guardian Password"));
        assert!(content.contains("Restore Guardian"));
    }
}
