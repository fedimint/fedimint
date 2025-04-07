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
use {fedimint_lnv2_server, fedimint_meta_server, fedimint_wallet_server};

use crate::assets::WithStaticRoutesExt as _;
use crate::layout::{self};
use crate::{
    AuthState, LoginInput, audit, bitcoin, check_auth, invite_code, latency, lnv2,
    login_form_response, login_submit_response, meta, wallet,
};

pub fn dashboard_layout(content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (layout::common_head("Dashboard"))
            }
            body {
                div class="container" {
                    header class="text-center" {
                        h1 class="header-title" { "Fedimint Guardian UI" }
                    }

                    (content)
                }
                script src="/assets/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
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

fn render_session_count(session_count: usize) -> Markup {
    html! {

        div id="session-count" class="alert alert-info" hx-swap-oob=(true) {
            "Session Count: " strong { (session_count) }
        }
    }
}
// Main dashboard view
async fn dashboard_view(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    let guardian_names = state.api.guardian_names().await;
    let federation_name = state.api.federation_name().await;
    let session_count = state.api.session_count().await;
    let consensus_ord_latency = state.api.consensus_ord_latency().await;
    let p2p_connection_status = state.api.p2p_connection_status().await;
    let invite_code = state.api.federation_invite_code().await;
    let audit_summary = state.api.federation_audit().await;
    let bitcoin_rpc_url = state.api.bitcoin_rpc_url().await;
    let bitcoin_rpc_status = state.api.bitcoin_rpc_status().await;

    // Conditionally add Lightning V2 UI if the module is available
    let lightning_content = html! {
        @if let Some(lightning) = state.api.get_module::<fedimint_lnv2_server::Lightning>() {
            (lnv2::render(lightning).await)
        }
    };

    // Conditionally add Wallet UI if the module is available
    let wallet_content = html! {
        @if let Some(wallet_module) = state.api.get_module::<fedimint_wallet_server::Wallet>() {
            (wallet::render(wallet_module).await)
        }
    };

    // Conditionally add Meta UI if the module is available
    let meta_content = html! {
        @if let Some(meta_module) = state.api.get_module::<fedimint_meta_server::Meta>() {
            (meta::render(meta_module).await)
        }
    };

    let content = html! {
        div class="row gy-4" {
            div class="col-md-6" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { (federation_name) }
                    div class="card-body" {
                        (render_session_count(session_count))
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

            // Invite Code Column
            div class="col-md-6" {
                (invite_code::render(&invite_code))
            }
        }

        // Second row: Audit Summary and Peer Status
        div class="row gy-4 mt-2" {
            // Audit Information Column
            div class="col-lg-6" {
                (audit::render(&audit_summary))
            }

            // Peer Connection Status Column
            div class="col-lg-6" {
                (latency::render(consensus_ord_latency, &p2p_connection_status))
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-12" {
                (bitcoin::render(bitcoin_rpc_url, &bitcoin_rpc_status))
            }
        }

        (lightning_content)
        (wallet_content)
        (meta_content)

        // Every 15s fetch updates to the page
        div hx-get="/dashboard/update" hx-trigger="every 15s" hx-swap="none" { }
    };

    Html(dashboard_layout(content).into_string()).into_response()
}

/// Periodic updated to the dashboard
///
/// We don't just replace the whole page, not to interfere with elements that
/// might not like it.
async fn dashboard_update(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    let session_count = state.api.session_count().await;
    let consensus_ord_latency = state.api.consensus_ord_latency().await;
    let p2p_connection_status = state.api.p2p_connection_status().await;

    // each element has an `id` and `hx-swap-oob=true` which on htmx requests
    // make them update themselves.
    let content = html! {
        (render_session_count(session_count))

        (latency::render(consensus_ord_latency, &p2p_connection_status))

        @if let Some(lightning) = state.api.get_module::<fedimint_lnv2_server::Lightning>() {
            (lnv2::render(lightning).await)
        }
    };

    Html(content.into_string()).into_response()
}

pub fn start(
    api: DynDashboardApi,
    ui_bind: SocketAddr,
    task_handle: TaskHandle,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    // Create a basic router with core routes
    let mut app = Router::new()
        .route("/", get(dashboard_view))
        .route("/dashboard/update", get(dashboard_update))
        .route("/login", get(login_form).post(login_submit))
        .with_static_routes();

    // Only add LNv2 gateway routes if the module exists
    if api
        .get_module::<fedimint_lnv2_server::Lightning>()
        .is_some()
    {
        app = app
            .route("/lnv2_gateway_add", post(lnv2::add_gateway))
            .route("/lnv2_gateway_remove", post(lnv2::remove_gateway));
    }

    // Only add Meta module routes if the module exists
    if api.get_module::<fedimint_meta_server::Meta>().is_some() {
        app = app
            .route("/meta/submit", post(meta::post_submit))
            .route("/meta/set", post(meta::post_set))
            .route("/meta/reset", post(meta::post_reset))
            .route("/meta/delete", post(meta::post_delete))
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
