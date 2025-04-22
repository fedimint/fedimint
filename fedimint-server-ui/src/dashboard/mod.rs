pub mod audit;
pub mod bitcoin;
pub mod general;
pub mod invite;
pub mod latency;
pub mod modules;

use axum::Router;
use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use maud::{DOCTYPE, Markup, html};
use {fedimint_lnv2_server, fedimint_meta_server, fedimint_wallet_server};

use crate::assets::WithStaticRoutesExt as _;
use crate::dashboard::modules::{lnv2, meta, wallet};
use crate::{
    AuthState, LoginInput, check_auth, common_head, login_form_response, login_submit_response,
};

pub fn dashboard_layout(content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (common_head("Dashboard"))
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

    let content = html! {
        div class="row gy-4" {
            div class="col-md-6" {
                (general::render(&federation_name, session_count, &guardian_names))
            }

            div class="col-md-6" {
                (invite::render(&invite_code))
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-lg-6" {
                (audit::render(&audit_summary))
            }

            div class="col-lg-6" {
                (latency::render(consensus_ord_latency, &p2p_connection_status))
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-12" {
                (bitcoin::render(bitcoin_rpc_url, &bitcoin_rpc_status))
            }
        }

        // Conditionally add Lightning V2 UI if the module is available
        @if let Some(lightning) = state.api.get_module::<fedimint_lnv2_server::Lightning>() {
            div class="row gy-4 mt-2" {
                div class="col-12" {
                    (lnv2::render(lightning).await)
                }
            }
        }

        // Conditionally add Wallet UI if the module is available
        @if let Some(wallet_module) = state.api.get_module::<fedimint_wallet_server::Wallet>() {
            div class="row gy-4 mt-2" {
                div class="col-12" {
                    (wallet::render(wallet_module).await)
                }
            }
        }

        // Conditionally add Meta UI if the module is available
        @if let Some(meta_module) = state.api.get_module::<fedimint_meta_server::Meta>() {
            div class="row gy-4 mt-2" {
                div class="col-12" {
                    (meta::render(meta_module).await)
                }
            }
        }
    };

    Html(dashboard_layout(content).into_string()).into_response()
}

pub fn router(api: DynDashboardApi) -> Router {
    let mut app = Router::new()
        .route("/", get(dashboard_view))
        .route("/login", get(login_form).post(login_submit))
        .with_static_routes();

    // routeradd LNv2 gateway routes if the module exists
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
    app.with_state(AuthState::new(api))
}
