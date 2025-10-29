pub mod assets;
pub(crate) mod auth;

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use fedimint_core::hex::ToHex;
use fedimint_core::secp256k1::rand::{Rng, thread_rng};
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;

use crate::assets::WithStaticRoutesExt;
use crate::auth::UserAuth;

pub const ROOT_ROUTE: &str = "/";
pub const LOGIN_ROUTE: &str = "/ui/login";

//pub type DynGatewayApi<E> = Arc<dyn IAdminGateway<Error = E> + Send + Sync +
// 'static>;
pub type DynGatewayApi = Arc<dyn IAdminGateway + Send + Sync + 'static>;

#[async_trait]
pub trait IAdminGateway {
    //type Error;

    //async fn handle_get_info(&self) -> Result<GatewayInfo, Self::Error>;

    fn get_password_hash(&self) -> String;
}

#[derive(Clone)]
pub struct UiState {
    pub api: DynGatewayApi,
    pub(crate) auth_cookie_name: String,
    pub(crate) auth_cookie_value: String,
}

impl UiState {
    pub fn new(api: DynGatewayApi) -> Self {
        Self {
            api,
            auth_cookie_name: thread_rng().r#gen::<[u8; 4]>().encode_hex(),
            auth_cookie_value: thread_rng().r#gen::<[u8; 32]>().encode_hex(),
        }
    }
}

pub fn common_head(title: &str) -> Markup {
    html! {
        meta charset="utf-8";
        meta name="viewport" content="width=device-width, initial-scale=1.0";
        title { "Gateway Dashboard"}
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
    password: String,
}

async fn login_form(State(_state): State<UiState>) -> impl IntoResponse {
    login_form_response()
}

pub(crate) fn login_form_response() -> impl IntoResponse {
    let content = html! {
        form method="post" action="/ui/login" {
            div class="form-group mb-4" {
                input type="password" class="form-control" id="password" name="password" placeholder="Your password" required;
            }
            div class="button-container" {
                button type="submit" class="btn btn-primary setup-btn" { "Log In" }
            }
        }
    };

    Html(login_layout("Fedimint Gateway Login", content).into_string()).into_response()
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
                                h1 class="header-title" { "Fedimint Gateway UI" }
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

// Dashboard login submit handler
async fn login_submit(
    State(state): State<UiState>,
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

        tracing::info!(?cookie, "Login submit successful, setting cookie");
        let jar = jar.add(cookie);
        return (jar, Redirect::to(ROOT_ROUTE)).into_response();
    }

    let content = html! {
        div class="alert alert-danger" { "The password is invalid" }
        div class="button-container" {
            a href="/ui/login" class="btn btn-primary setup-btn" { "Return to Login" }
        }
    };

    Html(login_layout("Login Failed", content).into_string()).into_response()
}

// Main dashboard view
async fn dashboard_view(State(_state): State<UiState>, _auth: UserAuth) -> impl IntoResponse {
    let content = html! {
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

    Html(dashboard_layout(content).into_string()).into_response()
}

pub fn dashboard_layout(content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (common_head("Dashboard"))
            }
            body {
                div class="container" {
                    header class="text-center mb-4" {
                        h1 class="header-title mb-1" { "Fedimint Gateway UI" }
                    }

                    (content)
                }
                script src="/assets/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
            }
        }
    }
}

//pub fn router<E: Clone + Send + Sync + 'static>(api: DynGatewayApi<E>) ->
// Router {
pub fn router(api: DynGatewayApi) -> Router {
    let app = Router::new()
        .route(ROOT_ROUTE, get(dashboard_view))
        .route(LOGIN_ROUTE, get(login_form).post(login_submit))
        .with_static_routes();

    app.with_state(UiState::new(api))
}
