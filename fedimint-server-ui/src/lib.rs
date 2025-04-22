pub mod assets;
pub mod dashboard;
pub mod setup;

use axum::response::{Html, IntoResponse, Redirect};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use fedimint_core::hex::ToHex;
use fedimint_core::module::ApiAuth;
use fedimint_core::secp256k1::rand::{Rng, thread_rng};
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;

pub(crate) const LOG_UI: &str = "fm::ui";

// Common route constants
pub const ROOT_ROUTE: &str = "/";
pub const LOGIN_ROUTE: &str = "/login";

pub fn common_head(title: &str) -> Markup {
    html! {
        meta charset="utf-8";
        meta name="viewport" content="width=device-width, initial-scale=1.0";
        title { "Guardian Dashboard"}
        link rel="stylesheet" href="/assets/bootstrap.min.css" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous";
        link rel="stylesheet" type="text/css" href="/assets/style.css";
        link rel="icon" type="image/png" href="/assets/logo.png";

        // Note: this needs to be included in the header, so that web-page does not
        // get in a state where htmx is not yet loaded. `deref` helps with blocking the load.
        // Learned the hard way. --dpc
        script defer src="/assets/htmx.org-2.0.4.min.js" {}

        title { (title) }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginInput {
    pub password: String,
}

/// Generic state for both setup and dashboard UIs
#[derive(Clone)]
pub struct AuthState<T> {
    pub(crate) api: T,
    pub(crate) auth_cookie_name: String,
    pub(crate) auth_cookie_value: String,
}

impl<T> AuthState<T> {
    pub fn new(api: T) -> Self {
        Self {
            api,
            auth_cookie_name: thread_rng().r#gen::<[u8; 4]>().encode_hex(),
            auth_cookie_value: thread_rng().r#gen::<[u8; 32]>().encode_hex(),
        }
    }
}

pub(crate) fn login_layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (common_head(title))
            }
            body {
                div class="container" {
                    div class="row justify-content-center" {
                        div class="col-md-8 col-lg-5 narrow-container" {
                            header class="text-center" {
                                h1 class="header-title" { "Fedimint Guardian UI" }
                            }

                            div class="card" {
                                div class="card-body" {
                                    (content)
                                }
                            }
                        }
                    }
                }
                script src="/assets/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
            }
        }
    }
}

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

pub(crate) async fn check_auth(
    auth_cookie_name: &str,
    auth_cookie_value: &str,
    jar: &CookieJar,
) -> bool {
    match jar.get(auth_cookie_name) {
        Some(cookie) => cookie.value() == auth_cookie_value,
        None => false,
    }
}
