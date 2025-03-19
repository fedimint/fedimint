use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use axum::Router;
use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use fedimint_core::task::TaskHandle;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use maud::{DOCTYPE, Markup, html};
use tokio::net::TcpListener;
use {fedimint_lnv2_server, fedimint_wallet_server};

use crate::{
    AuthState, LoginInput, audit, check_auth, common_styles, connection_status, invite_code, lnv2,
    login_form_response, login_submit_response, wallet,
};

pub fn dashboard_layout(content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Guardian Dashboard"}
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous";
                style {
                    (common_styles())
                    r#"
                    /* Dashboard-specific styles */
                    
                    /* Card header styling */
                    .card-header.dashboard-header {
                        font-size: 1.25rem;
                        font-weight: 600;
                        background-color: #f8f9fa;
                        padding: 1rem 1.25rem;
                    }
                    
                    /* Modal enhancements */
                    .modal-header {
                        border-bottom: 1px solid #dee2e6;
                        background-color: #f8f9fa;
                    }
                    
                    .modal-title {
                        font-weight: 600;
                    }
                    
                    .modal-footer {
                        border-top: 1px solid #dee2e6;
                    }
                    
                    /* Invite code text display */
                    .user-select-all {
                        user-select: all;
                        font-size: 0.85rem;
                        word-break: break-all;
                    }
                    
                    /* For larger screens */
                    @media (min-width: 1400px) {
                        .container {
                            max-width: 70% !important;
                        }
                    }
                    
                    /* QR Code Modal */
                    #inviteCodeModal .modal-dialog {
                        max-width: 360px;
                    }
                    
                    /* Copy button styling */
                    #copyInviteCodeBtn {
                        padding: 0.5rem 1.5rem;
                        font-size: 1rem;
                    }
                    "#
                }
            }
            body {
                div class="container" style="max-width: 66%;" {
                    header class="text-center" {
                        h1 class="header-title" { "Fedimint Guardian UI" }
                    }

                    (content)
                }
                script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
            }
        }
    }
}

// Dashboard login form handler
async fn login_form(State(_state): State<AuthState<DynDashboardApi>>) -> impl IntoResponse {
    login_form_response()
}

// Dashboard login submit handler
async fn login_submit(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    login_submit_response(
        state.api.auth().await,
        state.auth_cookie_name,
        state.auth_cookie_value,
        jar,
        input,
    )
    .into_response()
}

// Main dashboard view
async fn dashboard_view(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    let guardian_name = state.api.guardian_name().await;
    let federation_name = state.api.federation_name().await;
    let session_count = state.api.session_count().await;
    let peer_status = state.api.peer_connection_status().await;
    let invite_code = state.api.federation_invite_code().await;
    let audit_summary = state.api.federation_audit().await;

    let mut content = html! {
        div class="row gy-4" {
            // Guardian Information Column
            div class="col-md-6" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { "General Information" }
                    div class="card-body" {
                        table class="table" {
                            tr {
                                th { "Guardian Name" }
                                td { (guardian_name) }
                            }
                            tr {
                                th { "Federation Name" }
                                td { (federation_name) }
                            }
                            tr {
                                th { "Current Session Count" }
                                td { (session_count) }
                            }
                        }
                    }
                }
            }

            // Invite Code Column
            div class="col-md-6" {
                (invite_code::invite_code_card())
            }
        }

        // Render the invite code modal
        (invite_code::invite_code_modal(&invite_code))

        // Second row: Audit Summary and Peer Status
        div class="row gy-4 mt-2" {
            // Audit Information Column
            div class="col-lg-8" {
                (audit::render_audit_summary(&audit_summary))
            }

            // Peer Connection Status Column
            div class="col-lg-4" {
                (connection_status::render_connection_status(&peer_status))
            }
        }
    };

    // Conditionally add Lightning V2 UI if the module is available
    if let Some(lightning) = state.api.get_module::<fedimint_lnv2_server::Lightning>() {
        content = html! {
            (content)
            (lnv2::render(lightning).await)
        };
    }

    // Conditionally add Wallet UI if the module is available
    if let Some(wallet_module) = state.api.get_module::<fedimint_wallet_server::Wallet>() {
        content = html! {
            (content)
            (wallet::render(wallet_module).await)
        };
    }

    Html(dashboard_layout(content).into_string()).into_response()
}

pub fn start(
    api: DynDashboardApi,
    ui_bind: SocketAddr,
    task_handle: TaskHandle,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    // Create a basic router with core routes
    let mut app = Router::new()
        .route("/", get(dashboard_view))
        .route("/login", get(login_form).post(login_submit));

    // Only add LNv2 gateway routes if the module exists
    if api
        .get_module::<fedimint_lnv2_server::Lightning>()
        .is_some()
    {
        app = app
            .route("/lnv2_gateway_add", post(lnv2::add_gateway))
            .route("/lnv2_gateway_remove", post(lnv2::remove_gateway));
    }

    // Finalize the router with state
    let app = app.with_state(AuthState::new(api));

    Box::pin(async move {
        let listener = TcpListener::bind(ui_bind)
            .await
            .expect("Failed to bind dashboard UI");

        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(task_handle.make_shutdown_rx())
            .await
            .expect("Failed to serve dashboard UI");
    })
}
