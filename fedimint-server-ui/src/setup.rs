use std::collections::BTreeSet;

use axum::Router;
use axum::extract::State;
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
    connectivity_check_handler, connectivity_widget, login_form_response,
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use qrcode::QrCode;
use serde::Deserialize;

use crate::{common_head, login_submit_response};

// Setup route constants
pub const FEDERATION_SETUP_ROUTE: &str = "/federation_setup";
pub const ADD_SETUP_CODE_ROUTE: &str = "/add_setup_code";
pub const RESET_SETUP_CODES_ROUTE: &str = "/reset_setup_codes";
pub const START_DKG_ROUTE: &str = "/start_dkg";

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

pub fn setup_layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (common_head(title))
            }
            body {
                div class="container" {
                    div class="row justify-content-center" {
                        div class="col-md-8 col-lg-5 narrow-container" {
                            header class="text-center" {
                                h1 class="header-title" { "Fedimint Guardian UI" }
                            }

                            div class="card" {
                                div class="card-body" {
                                    (content)
                                }
                            }
                        }
                    }
                }
                (connectivity_widget())
                script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
                script src="/assets/html5-qrcode.min.js" {}
            }
        }
    }
}

// GET handler for the /setup route (display the setup form)
async fn setup_form(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_some() {
        return Redirect::to(FEDERATION_SETUP_ROUTE).into_response();
    }

    let available_modules = state.api.available_modules();
    let default_modules = state.api.default_modules();

    let content = html! {
        form method="post" action=(ROOT_ROUTE) {
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
                        input type="number" class="form-control" id="federation_size"
                            name="federation_size" min="1";
                        small class="form-text text-muted" {
                            "Federation size must be 1 or at least 4."
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
                                        @for kind in &available_modules {
                                            div class="form-check" {
                                                input type="checkbox" class="form-check-input"
                                                    id=(format!("module_{}", kind.as_str()))
                                                    name="enabled_modules"
                                                    value=(kind.as_str())
                                                    checked[default_modules.contains(kind)];

                                                label class="form-check-label" for=(format!("module_{}", kind.as_str())) {
                                                    (kind.as_str())
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

            div class="button-container" {
                button type="submit" class="btn btn-primary setup-btn" { "Confirm" }
            }
        }
    };

    Html(setup_layout("Setup Fedimint Guardian", content).into_string()).into_response()
}

// POST handler for the /setup route (process the password setup form)
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
                    let content = html! {
                        div class="alert alert-danger" { "Invalid federation size" }
                        div class="button-container" {
                            a href=(ROOT_ROUTE) class="btn btn-primary setup-btn" { "Return to Setup" }
                        }
                    };
                    return Html(setup_layout("Setup Error", content).into_string())
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
            ApiAuth(input.password),
            input.name,
            federation_name,
            disable_base_fees,
            enabled_modules,
            federation_size,
        )
        .await
    {
        Ok(_) => Redirect::to(LOGIN_ROUTE).into_response(),
        Err(e) => {
            let content = html! {
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href=(ROOT_ROUTE) class="btn btn-primary setup-btn" { "Return to Setup" }
                }
            };

            Html(setup_layout("Setup Error", content).into_string()).into_response()
        }
    }
}

// GET handler for the /login route (display the login form)
async fn login_form(State(state): State<UiState<DynSetupApi>>) -> impl IntoResponse {
    if state.api.setup_code().await.is_none() {
        return Redirect::to(ROOT_ROUTE).into_response();
    }

    login_form_response("Fedimint Guardian Login").into_response()
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

    let connected_peers = state.api.connected_peers().await;
    let guardian_name = state.api.guardian_name().await;
    let federation_size = state.api.federation_size().await;
    let cfg_federation_name = state.api.cfg_federation_name().await;
    let cfg_base_fees_disabled = state.api.cfg_base_fees_disabled().await;
    let cfg_enabled_modules = state.api.cfg_enabled_modules().await;
    let total_guardians = connected_peers.len() + 1;
    let can_start_dkg = federation_size
        .map(|expected| total_guardians == expected as usize)
        .unwrap_or(false);

    let content = html! {
        @if let Some(ref name) = guardian_name {
            section class="mb-4" {
                h4 { "Your name" }
                p { (name) }
            }
        }

        section class="mb-4" {
            h4 { "Federation settings" }
            @if cfg_federation_name.is_some() || federation_size.is_some() || cfg_base_fees_disabled.is_some() || cfg_enabled_modules.is_some() {
                ul class="list-group list-group-flush" {
                    @if let Some(ref name) = cfg_federation_name {
                        li class="list-group-item" {
                            strong { "Federation name: " }
                            (name)
                        }
                    }
                    @if let Some(size) = federation_size {
                        li class="list-group-item" {
                            strong { "Federation size: " }
                            (size)
                        }
                    }
                    @if let Some(disabled) = cfg_base_fees_disabled {
                        li class="list-group-item" {
                            strong { "Base fees: " }
                            @if disabled { "disabled" } @else { "enabled" }
                        }
                    }
                    @if let Some(ref modules) = cfg_enabled_modules {
                        li class="list-group-item" {
                            strong { "Enabled modules: " }
                            (modules.iter().map(|m| m.as_str().to_owned()).collect::<Vec<_>>().join(", "))
                        }
                    }
                }
            } @else {
                p class="text-muted" { "Leader's setup code not provided yet." }
            }
        }

        hr class="my-4" {}

        section class="mb-4" {
            h4 { "Your setup code" }

            p { "Share it with other guardians." }

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

            div class="alert alert-info mb-3" {
                (our_connection_info)
            }

            div class="text-center" {
                button type="button" class="btn btn-outline-primary setup-btn"
                    onclick=(format!("navigator.clipboard.writeText('{}')", our_connection_info)) {
                    "Copy to Clipboard"
                }
            }
        }

        hr class="my-4" {}

        section class="mb-4" {
            h4 { "Other guardians" }

            @if let Some(expected) = federation_size {
                p { (format!("{total_guardians} of {expected} guardians connected.")) }
            } @else {
                p { "Add setup code of every other guardian." }
            }

            ul class="list-group mb-4" {
                @for peer in connected_peers {
                    li class="list-group-item" { (peer) }
                }
            }

            form method="post" action=(ADD_SETUP_CODE_ROUTE) {
                div class="mb-3" {
                    div class="input-group" {
                        input type="text" class="form-control" id="peer_info" name="peer_info"
                            placeholder="Paste setup code" required;
                        button type="button" class="btn btn-outline-secondary" onclick="startQrScanner()" title="Scan QR Code" {
                            (PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M15 12a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h1.172a3 3 0 0 0 2.12-.879l.83-.828A1 1 0 0 1 6.827 3h2.344a1 1 0 0 1 .707.293l.828.828A3 3 0 0 0 12.828 5H14a1 1 0 0 1 1 1zM2 4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-1.172a2 2 0 0 1-1.414-.586l-.828-.828A2 2 0 0 0 9.172 2H6.828a2 2 0 0 0-1.414.586l-.828.828A2 2 0 0 1 3.172 4z"/><path d="M8 11a2.5 2.5 0 1 1 0-5 2.5 2.5 0 0 1 0 5m0 1a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7M3 6.5a.5.5 0 1 1-1 0 .5.5 0 0 1 1 0"/></svg>"#))
                        }
                    }
                }

                div class="row mt-3" {
                    div class="col-6" {
                        button type="button" class="btn btn-warning w-100" onclick="if(confirm('Are you sure you want to reset all guardians?')){document.getElementById('reset-form').submit();}" {
                            "Reset Guardians"
                        }
                    }

                    div class="col-6" {
                        button type="submit" class="btn btn-primary w-100" { "Add Guardian" }
                    }
                }
            }

            form id="reset-form" method="post" action=(RESET_SETUP_CODES_ROUTE) class="d-none" {}
        }

        hr class="my-4" {}

        section class="mb-4" {
            div class="alert alert-warning mb-4" {
                "Verify " b { "all" } " other guardians were added. This process cannot be reversed once started."
            }

            div class="text-center" {
                form method="post" action=(START_DKG_ROUTE) {
                    button type="submit" class="btn btn-warning setup-btn"
                        disabled[!can_start_dkg] {
                        "🚀 Confirm"
                    }
                }
                @if !can_start_dkg {
                    @if let Some(expected) = federation_size {
                        p class="text-muted mt-2" style="font-size: 0.875rem;" {
                            (format!("Need to collect all {expected} setup codes."))
                        }
                    } @else {
                        p class="text-muted mt-2" style="font-size: 0.875rem;" {
                            "Need to collect the setup code from the leader and other guardians."
                        }
                    }
                }
            }
        }

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

    Html(setup_layout("Federation Setup", content).into_string()).into_response()
}

// POST handler for adding peer connection info
async fn post_add_setup_code(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
    Form(input): Form<PeerInfoInput>,
) -> impl IntoResponse {
    match state.api.add_peer_setup_code(input.peer_info).await {
        Ok(..) => Redirect::to(FEDERATION_SETUP_ROUTE).into_response(),
        Err(e) => {
            let content = html! {
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href=(FEDERATION_SETUP_ROUTE) class="btn btn-primary setup-btn" { "Return to Setup" }
                }
            };

            Html(setup_layout("Error", content).into_string()).into_response()
        }
    }
}

// POST handler for starting the DKG process
async fn post_start_dkg(
    State(state): State<UiState<DynSetupApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    let our_connection_info = state.api.setup_code().await;

    match state.api.start_dkg().await {
        Ok(()) => {
            // Show DKG progress page with htmx polling
            let content = html! {
                div class="alert alert-success my-4" {
                    "Setting up Federation..."
                }

                p class="text-center" {
                    "All guardians need to confirm their settings. Once completed you will be redirected to the Dashboard."
                }

                @if let Some(ref info) = our_connection_info {
                    hr class="my-4" {}
                    section class="mb-4" {
                        h4 { "Your setup code" }
                        p { "Share with guardians who still need it." }
                        div class="alert alert-info mb-3" {
                            (info)
                        }
                        div class="text-center" {
                            button type="button" class="btn btn-outline-primary setup-btn"
                                onclick=(format!("navigator.clipboard.writeText('{info}')")) {
                                "Copy to Clipboard"
                            }
                        }
                    }
                }

                // Hidden div that will poll and redirect when the normal UI is ready
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

            Html(setup_layout("DKG Started", content).into_string()).into_response()
        }
        Err(e) => {
            let content = html! {
                div class="alert alert-danger" { (e.to_string()) }
                div class="button-container" {
                    a href=(FEDERATION_SETUP_ROUTE) class="btn btn-primary setup-btn" { "Return to Setup" }
                }
            };

            Html(setup_layout("Error", content).into_string()).into_response()
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
        .route(LOGIN_ROUTE, get(login_form).post(login_submit))
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
