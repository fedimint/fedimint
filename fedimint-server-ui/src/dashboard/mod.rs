pub mod audit;
pub mod bitcoin;
pub(crate) mod consensus_explorer;
pub mod general;
pub mod invite;
pub mod latency;
pub mod modules;

use axum::Router;
use axum::body::Body;
use axum::extract::{Form, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use consensus_explorer::consensus_explorer_view;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use maud::{DOCTYPE, Markup, html};
use {fedimint_lnv2_server, fedimint_meta_server, fedimint_wallet_server};

use crate::assets::WithStaticRoutesExt as _;
use crate::auth::UserAuth;
use crate::dashboard::modules::{lnv2, meta, wallet};
use crate::{
    DOWNLOAD_BACKUP_ROUTE, EXPLORER_IDX_ROUTE, EXPLORER_ROUTE, LOGIN_ROUTE, LoginInput, ROOT_ROUTE,
    UiState, common_head, login_form_response, login_submit_response,
};

pub fn dashboard_layout(content: Markup, fedimintd_version: Option<&str>) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (common_head("Dashboard"))
            }
            body {
                div class="container" {
                    header class="text-center mb-4" {
                        h1 class="header-title mb-1" { "Fedimint Guardian UI" }
                        @if let Some(version) = fedimintd_version {
                            div {
                                small class="text-muted" { "v" (version) }
                            }
                        }
                    }

                    (content)
                }
                script src="/assets/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
            }
        }
    }
}

// Dashboard login form handler
async fn login_form(State(_state): State<UiState<DynDashboardApi>>) -> impl IntoResponse {
    login_form_response()
}

// Dashboard login submit handler
async fn login_submit(
    State(state): State<UiState<DynDashboardApi>>,
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

// Download backup handler
async fn download_backup(
    State(state): State<UiState<DynDashboardApi>>,
    user_auth: UserAuth,
) -> impl IntoResponse {
    let api_auth = state.api.auth().await;
    let backup = state
        .api
        .download_guardian_config_backup(&api_auth.0, &user_auth.guardian_auth_token)
        .await;
    let filename = "guardian-backup.tar";

    Response::builder()
        .header(header::CONTENT_TYPE, "application/x-tar")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(backup.tar_archive_bytes))
        .expect("Failed to build response")
}

// Main dashboard view
async fn dashboard_view(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
) -> impl IntoResponse {
    let guardian_names = state.api.guardian_names().await;
    let federation_name = state.api.federation_name().await;
    let session_count = state.api.session_count().await;
    let fedimintd_version = state.api.fedimintd_version().await;
    let consensus_ord_latency = state.api.consensus_ord_latency().await;
    let p2p_connection_status = state.api.p2p_connection_status().await;
    let p2p_connection_type_status = state.api.p2p_connection_type_status().await;
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
                (latency::render(consensus_ord_latency, &p2p_connection_status, &p2p_connection_type_status))
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

        // Guardian Configuration Backup section
        div class="row gy-4 mt-4" {
            div class="col-12" {
                div class="card" {
                    div class="card-header bg-warning text-dark" {
                        h5 class="mb-0" { "Guardian Configuration Backup" }
                    }
                    div class="card-body" {
                        div class="row" {
                            div class="col-lg-6 mb-3 mb-lg-0" {
                                p {
                                    "You only need to download this backup once."
                                }
                                p {
                                    "Use it to restore your guardian if your server fails."
                                }
                                a href="/download-backup" class="btn btn-outline-warning btn-lg mt-2" {
                                    "Download Guardian Backup"
                                }
                            }
                            div class="col-lg-6" {
                                div class="alert alert-warning mb-0" {
                                    strong { "Security Warning" }
                                    br;
                                    "Store this file securely since anyone with it and your password can run your guardian node."
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    Html(dashboard_layout(content, Some(&fedimintd_version)).into_string()).into_response()
}

pub fn router(api: DynDashboardApi) -> Router {
    let mut app = Router::new()
        .route(ROOT_ROUTE, get(dashboard_view))
        .route(LOGIN_ROUTE, get(login_form).post(login_submit))
        .route(EXPLORER_ROUTE, get(consensus_explorer_view))
        .route(EXPLORER_IDX_ROUTE, get(consensus_explorer_view))
        .route(DOWNLOAD_BACKUP_ROUTE, get(download_backup))
        .with_static_routes();

    // routeradd LNv2 gateway routes if the module exists
    if api
        .get_module::<fedimint_lnv2_server::Lightning>()
        .is_some()
    {
        app = app
            .route(lnv2::LNV2_ADD_ROUTE, post(lnv2::post_add))
            .route(lnv2::LNV2_REMOVE_ROUTE, post(lnv2::post_remove));
    }

    // Only add Meta module routes if the module exists
    if api.get_module::<fedimint_meta_server::Meta>().is_some() {
        app = app
            .route(meta::META_SUBMIT_ROUTE, post(meta::post_submit))
            .route(meta::META_SET_ROUTE, post(meta::post_set))
            .route(meta::META_RESET_ROUTE, post(meta::post_reset))
            .route(meta::META_DELETE_ROUTE, post(meta::post_delete));
    }

    // Finalize the router with state
    app.with_state(UiState::new(api))
}
