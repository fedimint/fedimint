use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use fedimint_gateway_common::{GatewayInfo, LightningMode};
use fedimint_ui_common::assets::WithStaticRoutesExt;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{
    LOGIN_ROUTE, LoginInput, ROOT_ROUTE, UiState, dashboard_layout, login_form_response,
    login_layout,
};
use maud::html;

pub type DynGatewayApi<E> = Arc<dyn IAdminGateway<Error = E> + Send + Sync + 'static>;

#[async_trait]
pub trait IAdminGateway {
    type Error;

    async fn handle_get_info(&self) -> Result<GatewayInfo, Self::Error>;

    fn get_password_hash(&self) -> String;

    fn gatewayd_version(&self) -> String;
}

async fn login_form<E>(State(_state): State<UiState<DynGatewayApi<E>>>) -> impl IntoResponse {
    login_form_response("Fedimint Gateway Login")
}

// Dashboard login submit handler
async fn login_submit<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> impl IntoResponse {
    if bcrypt::verify(input.password, &state.api.get_password_hash())
        .expect("bcyrpt hash should be valid")
    {
        let mut cookie = Cookie::new(state.auth_cookie_name.clone(), state.auth_cookie_value);
        cookie.set_path(ROOT_ROUTE);

        cookie.set_http_only(true);
        cookie.set_same_site(Some(SameSite::Lax));

        let jar = jar.add(cookie);
        return (jar, Redirect::to(ROOT_ROUTE)).into_response();
    }

    let content = html! {
        div class="alert alert-danger" { "The password is invalid" }
        div class="button-container" {
            a href=(LOGIN_ROUTE) class="btn btn-primary setup-btn" { "Return to Login" }
        }
    };

    Html(login_layout("Login Failed", content).into_string()).into_response()
}

async fn dashboard_view<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
) -> impl IntoResponse
where
    E: std::fmt::Display,
{
    let gateway_info = match state.api.handle_get_info().await {
        Ok(info) => info,
        Err(err) => {
            let content = html! {
                div class="alert alert-danger mt-4" {
                    strong { "Failed to fetch gateway info: " }
                    (err.to_string())
                }
            };
            return Html(dashboard_layout(content, "Fedimint Gateway UI", None).into_string())
                .into_response();
        }
    };
    let gatewayd_version = state.api.gatewayd_version();

    let content = html! {

        // Top row
        div class="row gy-4" {

            // General Info
            div class="col-md-6" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { "Gateway Information" }
                    div class="card-body" {
                        div id="status" class="alert alert-info" {
                            "Status: " strong { (gateway_info.gateway_state.clone()) }
                        }

                        table class="table table-sm mb-0" {
                            tbody {
                                tr {
                                    th { "Gateway ID" }
                                    td { (gateway_info.gateway_id.to_string()) }
                                }
                                tr {
                                    th { "Network" }
                                    td { (gateway_info.network.to_string()) }
                                }
                                tr {
                                    th { "Synced to Chain" }
                                    td { (gateway_info.synced_to_chain) }
                                }
                                @if let Some(block_height) = gateway_info.block_height {
                                    tr {
                                        th { "Block Height" }
                                        td { (block_height) }
                                    }
                                }
                                tr {
                                    th { "API Endpoint" }
                                    td { (gateway_info.api.to_string()) }
                                }
                            }
                        }
                    }
                }
            }

            div class="col-md-6" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { "Lightning" }
                    div class="card-body" {
                        @match gateway_info.lightning_mode {
                            LightningMode::Lnd { lnd_rpc_addr, lnd_tls_cert, lnd_macaroon } => {
                                div id="node-type" class="alert alert-info" {
                                    "Node Type: " strong { ("External LND") }
                                }
                                table class="table table-sm mb-0" {
                                    tbody {
                                        tr {
                                            th { "RPC Address" }
                                            td { (lnd_rpc_addr) }
                                        }
                                        tr {
                                            th { "TLS Cert" }
                                            td { (lnd_tls_cert) }
                                        }
                                        tr {
                                            th { "Macaroon" }
                                            td { (lnd_macaroon) }
                                        }
                                        @if let Some(alias) = gateway_info.lightning_alias {
                                            tr {
                                                th { "Lightning Alias" }
                                                td { (alias) }
                                            }
                                        }
                                        @if let Some(pubkey) = gateway_info.lightning_pub_key {
                                            tr {
                                                th { "Lightning Public Key" }
                                                td { (pubkey) }
                                            }
                                        }
                                    }
                                }
                            }
                            LightningMode::Ldk { lightning_port, alias: _alias } => {
                                div id="node-type" class="alert alert-info" {
                                    "Node Type: " strong { ("Internal LDK") }
                                }
                                table class="table table-sm mb-0" {
                                    tbody {
                                        tr {
                                            th { "Port" }
                                            td { (lightning_port) }
                                        }
                                        @if let Some(alias) = gateway_info.lightning_alias {
                                            tr {
                                                th { "Alias" }
                                                td { (alias) }
                                            }
                                        }
                                        @if let Some(pubkey) = gateway_info.lightning_pub_key {
                                            tr {
                                                th { "Public Key" }
                                                td { (pubkey) }
                                            }
                                            @if let Some(host) = gateway_info.api.host_str() {
                                                tr {
                                                    th { "Connection String" }
                                                    td { (format!("{pubkey}@{host}:{lightning_port}")) }
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
    };

    Html(dashboard_layout(content, "Fedimint Gateway UI", Some(&gatewayd_version)).into_string())
        .into_response()
}

pub fn router<E: Display + 'static>(api: DynGatewayApi<E>) -> Router {
    let app = Router::new()
        .route(ROOT_ROUTE, get(dashboard_view))
        .route(LOGIN_ROUTE, get(login_form).post(login_submit))
        .with_static_routes();

    app.with_state(UiState::new(api))
}
