pub(crate) mod auth;
pub mod dashboard;
pub mod setup;

use axum::response::{Html, IntoResponse, Redirect};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use fedimint_core::module::ApiAuth;
use fedimint_ui_common::{LoginInput, common_head, login_layout};
use maud::html;

pub(crate) const LOG_UI: &str = "fm::ui";

// Common route constants
pub const ROOT_ROUTE: &str = "/";
pub const LOGIN_ROUTE: &str = "/login";
pub const EXPLORER_IDX_ROUTE: &str = "/explorer";
pub const EXPLORER_ROUTE: &str = "/explorer/{session_idx}";
pub const DOWNLOAD_BACKUP_ROUTE: &str = "/download-backup";

pub(crate) fn login_form_response() -> impl IntoResponse {
    let content = html! {
        form method="post" action="/login" {
            div class="form-group mb-4" {
                input type="password" class="form-control" id="password" name="password" placeholder="Your password" required;
            }
            div class="button-container" {
                button type="submit" class="btn btn-primary setup-btn" { "Log In" }
            }
        }
    };

    Html(login_layout("Fedimint Guardian Login", content).into_string()).into_response()
}

pub(crate) fn login_submit_response(
    auth: ApiAuth,
    auth_cookie_name: String,
    auth_cookie_value: String,
    jar: CookieJar,
    input: LoginInput,
) -> impl IntoResponse {
    if auth.0 == input.password {
        let mut cookie = Cookie::new(auth_cookie_name, auth_cookie_value);

        cookie.set_http_only(true);
        cookie.set_same_site(Some(SameSite::Lax));

        return (jar.add(cookie), Redirect::to("/")).into_response();
    }

    let content = html! {
        div class="alert alert-danger" { "The password is invalid" }
        div class="button-container" {
            a href="/login" class="btn btn-primary setup-btn" { "Return to Login" }
        }
    };

    Html(login_layout("Login Failed", content).into_string()).into_response()
}
