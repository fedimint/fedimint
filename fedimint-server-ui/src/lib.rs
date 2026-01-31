pub mod dashboard;
pub mod setup;

use axum::response::{Html, IntoResponse, Redirect};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use fedimint_core::module::ApiAuth;
use fedimint_ui_common::{LoginInput, common_head, login_layout};
use maud::html;
use serde::Deserialize;

pub(crate) const LOG_UI: &str = "fm::ui";

// Common route constants
pub const EXPLORER_IDX_ROUTE: &str = "/explorer";
pub const EXPLORER_ROUTE: &str = "/explorer/{session_idx}";
pub const DOWNLOAD_BACKUP_ROUTE: &str = "/download-backup";
pub const CHANGE_PASSWORD_ROUTE: &str = "/change-password";
pub const METRICS_ROUTE: &str = "/metrics";

#[derive(Debug, Deserialize)]
pub struct PasswordChangeInput {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
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
