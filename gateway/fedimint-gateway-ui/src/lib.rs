mod connect_fed;
mod federation;
mod general;
mod lightning;
mod mnemonic;
mod payment_summary;

use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use fedimint_core::secp256k1::serde::Deserialize;
use fedimint_gateway_common::{
    ConnectFedPayload, FederationInfo, GatewayInfo, LeaveFedPayload, MnemonicResponse,
    PaymentSummaryPayload, PaymentSummaryResponse, SetFeesPayload,
};
use fedimint_ui_common::assets::WithStaticRoutesExt;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{
    LOGIN_ROUTE, LoginInput, ROOT_ROUTE, UiState, dashboard_layout, login_form_response,
    login_layout,
};
use maud::html;

use crate::connect_fed::connect_federation_handler;
use crate::federation::{leave_federation_handler, set_fees_handler};
use crate::lightning::channels_fragment_handler;

pub type DynGatewayApi<E> = Arc<dyn IAdminGateway<Error = E> + Send + Sync + 'static>;

pub(crate) const CHANNEL_FRAGMENT_ROUTE: &str = "/channels/fragment";
pub(crate) const LEAVE_FEDERATION_ROUTE: &str = "/ui/federations/{id}/leave";
pub(crate) const CONNECT_FEDERATION_ROUTE: &str = "/ui/federations/join";
pub(crate) const SET_FEES_ROUTE: &str = "/ui/federation/set-fees";

#[derive(Default, Deserialize)]
pub struct DashboardQuery {
    pub success: Option<String>,
    pub ui_error: Option<String>,
}

fn redirect_success(msg: String) -> impl IntoResponse {
    let encoded: String = url::form_urlencoded::byte_serialize(msg.as_bytes()).collect();
    Redirect::to(&format!("/?success={}", encoded))
}

fn redirect_error(msg: String) -> impl IntoResponse {
    let encoded: String = url::form_urlencoded::byte_serialize(msg.as_bytes()).collect();
    Redirect::to(&format!("/?ui_error={}", encoded))
}

#[async_trait]
pub trait IAdminGateway {
    type Error;

    async fn handle_get_info(&self) -> Result<GatewayInfo, Self::Error>;

    async fn handle_list_channels_msg(
        &self,
    ) -> Result<Vec<fedimint_gateway_common::ChannelInfo>, Self::Error>;

    async fn handle_payment_summary_msg(
        &self,
        PaymentSummaryPayload {
            start_millis,
            end_millis,
        }: PaymentSummaryPayload,
    ) -> Result<PaymentSummaryResponse, Self::Error>;

    async fn handle_leave_federation(
        &self,
        payload: LeaveFedPayload,
    ) -> Result<FederationInfo, Self::Error>;

    async fn handle_connect_federation(
        &self,
        payload: ConnectFedPayload,
    ) -> Result<FederationInfo, Self::Error>;

    async fn handle_set_fees_msg(&self, payload: SetFeesPayload) -> Result<(), Self::Error>;

    async fn handle_mnemonic_msg(&self) -> Result<MnemonicResponse, Self::Error>;

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
    if let Ok(verify) = bcrypt::verify(input.password, &state.api.get_password_hash())
        && verify
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
    Query(msg): Query<DashboardQuery>,
) -> impl IntoResponse
where
    E: std::fmt::Display,
{
    let gatewayd_version = state.api.gatewayd_version();
    let gateway_info = match state.api.handle_get_info().await {
        Ok(info) => info,
        Err(err) => {
            let content = html! {
                div class="alert alert-danger mt-4" {
                    strong { "Failed to fetch gateway info: " }
                    (err.to_string())
                }
            };
            return Html(
                dashboard_layout(content, "Fedimint Gateway UI", Some(&gatewayd_version))
                    .into_string(),
            )
            .into_response();
        }
    };

    let content = html! {

       (federation::scripts())

        @if let Some(success) = msg.success {
            div class="alert alert-success mt-2 d-flex justify-content-between align-items-center" {
                span { (success) }
                a href=(ROOT_ROUTE)
                class="ms-3 text-decoration-none text-dark fw-bold"
                style="font-size: 1.5rem; line-height: 1; cursor: pointer;"
                { "×" }
            }
        }
        @if let Some(error) = msg.ui_error {
            div class="alert alert-danger mt-2 d-flex justify-content-between align-items-center" {
                span { (error) }
                a href=(ROOT_ROUTE)
                class="ms-3 text-decoration-none text-dark fw-bold"
                style="font-size: 1.5rem; line-height: 1; cursor: pointer;"
                { "×" }
            }
        }

        div class="row gy-4" {
            div class="col-md-6" {
                (general::render(&gateway_info))
            }
            div class="col-md-6" {
                (payment_summary::render(&state.api).await)
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-md-6" {
                (mnemonic::render(&state.api).await)
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-md-12" {
                (lightning::render(&gateway_info, &state.api).await)
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-md-12" {
                (connect_fed::render())
            }
        }

        @for fed in gateway_info.federations {
            (federation::render(&fed))
        }
    };

    Html(dashboard_layout(content, "Fedimint Gateway UI", Some(&gatewayd_version)).into_string())
        .into_response()
}

pub fn router<E: Display + 'static>(api: DynGatewayApi<E>) -> Router {
    let app = Router::new()
        .route(ROOT_ROUTE, get(dashboard_view))
        .route(LOGIN_ROUTE, get(login_form).post(login_submit))
        .route(CHANNEL_FRAGMENT_ROUTE, get(channels_fragment_handler))
        .route(LEAVE_FEDERATION_ROUTE, post(leave_federation_handler))
        .route(CONNECT_FEDERATION_ROUTE, post(connect_federation_handler))
        .route(SET_FEES_ROUTE, post(set_fees_handler))
        .with_static_routes();

    app.with_state(UiState::new(api))
}
