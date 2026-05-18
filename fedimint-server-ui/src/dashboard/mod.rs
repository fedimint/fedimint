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
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use consensus_explorer::consensus_explorer_view;
use fedimint_metrics::{Encoder, REGISTRY, TextEncoder};
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use fedimint_ui_common::assets::WithStaticRoutesExt;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{
    CONNECTIVITY_CHECK_ROUTE, LOGIN_ROUTE, LoginInput, ROOT_ROUTE, UiState,
    connectivity_check_handler, dashboard_layout, login_form, login_submit_response,
    single_card_layout,
};
use maud::html;
use {
    fedimint_lnv2_server, fedimint_meta_server, fedimint_mintv2_server, fedimint_wallet_server,
    fedimint_walletv2_server,
};

use crate::dashboard::modules::{lnv2, meta, mintv2, wallet, walletv2};
use crate::{DOWNLOAD_BACKUP_ROUTE, EXPLORER_IDX_ROUTE, EXPLORER_ROUTE, METRICS_ROUTE};

// Dashboard login form handler
async fn login_form_handler() -> impl IntoResponse {
    Html(single_card_layout("Enter Password", login_form(None)).into_string())
}

// Dashboard login submit handler. Only mounted when the guardian has a
// password configured, so `auth()` is always `Some` here.
async fn login_submit(
    State(state): State<UiState<DynDashboardApi>>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    login_submit_response(
        state
            .api
            .auth_ui()
            .expect("login route is mounted only when auth is configured"),
        state.auth_cookie_name,
        state.auth_cookie_value,
        jar,
        input,
    )
}

// Download backup handler
async fn download_backup(
    State(state): State<UiState<DynDashboardApi>>,
    user_auth: UserAuth,
) -> impl IntoResponse {
    let backup = state
        .api
        .download_guardian_config_backup(&user_auth.guardian_auth_token)
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

// Prometheus metrics handler
async fn metrics_handler(_user_auth: UserAuth) -> impl IntoResponse {
    let metric_families = REGISTRY.gather();
    let result = || -> Result<String, Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    };
    match result() {
        Ok(metrics) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            metrics,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")).into_response(),
    }
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
                (invite::render(&invite_code, session_count))
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

        // Conditionally add Wallet V2 UI if the module is available
        @if let Some(walletv2_module) = state.api.get_module::<fedimint_walletv2_server::Wallet>() {
            (walletv2::render(walletv2_module).await)
        }

        // Conditionally add Mint V2 UI if the module is available
        @if let Some(mint_module) = state.api.get_module::<fedimint_mintv2_server::Mint>() {
            div class="row gy-4 mt-2" {
                div class="col-12" {
                    (mintv2::render(mint_module).await)
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

        // Guardian Backup
        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card" {
                    div class="card-header dashboard-header" { "Guardian Backup" }
                    div class="card-body" {
                        div class="alert alert-warning mb-3" {
                            "You only need to download this backup once. Use it to restore your guardian if your server fails. Store this file securely since anyone with it can run your guardian node."
                        }
                        a href="/download-backup" class="btn btn-primary" {
                            "Download"
                        }
                    }
                }
            }
        }
    };

    Html(dashboard_layout(content, &fedimintd_version).into_string()).into_response()
}

pub fn router(api: DynDashboardApi) -> Router {
    let requires_auth = api.auth_ui().is_some();

    let mut app = Router::new()
        .route(ROOT_ROUTE, get(dashboard_view))
        .route(EXPLORER_ROUTE, get(consensus_explorer_view))
        .route(EXPLORER_IDX_ROUTE, get(consensus_explorer_view))
        .route(DOWNLOAD_BACKUP_ROUTE, get(download_backup))
        .route(METRICS_ROUTE, get(metrics_handler))
        .route(
            CONNECTIVITY_CHECK_ROUTE,
            get(connectivity_check_handler::<DynDashboardApi>),
        )
        .with_static_routes();

    if requires_auth {
        app = app.route(LOGIN_ROUTE, get(login_form_handler).post(login_submit));
    }

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
            .route(meta::META_DELETE_ROUTE, post(meta::post_delete))
            .route(meta::META_MERGE_ROUTE, post(meta::post_merge))
            .route(meta::META_VALUE_INPUT_ROUTE, get(meta::get_value_input));
    }

    // Finalize the router with state
    app.with_state(UiState::new(api, requires_auth))
}
