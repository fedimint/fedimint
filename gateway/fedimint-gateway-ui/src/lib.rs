mod federation;
mod general;
mod lightning;

use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use fedimint_gateway_common::GatewayInfo;
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

    async fn handle_list_channels_msg(
        &self,
    ) -> Result<Vec<fedimint_gateway_common::ChannelInfo>, Self::Error>;

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
        div class="row gy-4" {
            div class="col-md-12" {
                (general::render(&gateway_info))
            }
        }

        div class="row gy-4 mt-2" {
            div class="col-md-12" {
                (lightning::render(&gateway_info, &state.api).await)
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
        .with_static_routes();

    app.with_state(UiState::new(api))
}
