pub(crate) mod assets;
pub mod audit;
pub mod bitcoin;
pub mod dashboard;
pub(crate) mod error;
pub mod invite_code;
pub mod latency;
pub(crate) mod layout;
pub mod lnv2;
pub mod meta;
pub mod setup;
pub mod wallet;

use axum::response::{Html, IntoResponse, Redirect};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use fedimint_core::hex::ToHex;
use fedimint_core::module::ApiAuth;
use fedimint_core::secp256k1::rand::{Rng, thread_rng};
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;

pub(crate) const LOG_UI: &str = "fm::ui";

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
                (layout::common_head(title))
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
