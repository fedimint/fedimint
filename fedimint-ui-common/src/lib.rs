pub mod assets;
pub mod auth;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use fedimint_core::hex::ToHex;
use fedimint_core::module::ApiAuth;
use fedimint_core::secp256k1::rand::{Rng, thread_rng};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const ROOT_ROUTE: &str = "/";
pub const LOGIN_ROUTE: &str = "/login";
pub const CONNECTIVITY_CHECK_ROUTE: &str = "/ui/connectivity-check";

/// Generic state for both setup and dashboard UIs
#[derive(Clone)]
pub struct UiState<T> {
    pub api: T,
    pub auth_cookie_name: String,
    pub auth_cookie_value: String,
    /// Whether the UI requires a password login. When `false` (passwordless
    /// mode), the `UserAuth` extractor auto-passes and the `/login` route
    /// should not be mounted.
    pub requires_auth: bool,
}

impl<T> UiState<T> {
    pub fn new(api: T, requires_auth: bool) -> Self {
        Self {
            api,
            auth_cookie_name: thread_rng().r#gen::<[u8; 4]>().encode_hex(),
            auth_cookie_value: thread_rng().r#gen::<[u8; 32]>().encode_hex(),
            requires_auth,
        }
    }
}

pub fn common_head(title: &str) -> Markup {
    html! {
        meta charset="utf-8";
        meta name="viewport" content="width=device-width, initial-scale=1.0";
        link rel="stylesheet" href="/assets/bootstrap.min.css" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous";
        link rel="stylesheet" href="/assets/bootstrap-icons.min.css";
        link rel="stylesheet" type="text/css" href="/assets/style.css";
        link rel="icon" type="image/png" href="/assets/logo.png";

        // Note: this needs to be included in the header, so that web-page does not
        // get in a state where htmx is not yet loaded. `deref` helps with blocking the load.
        // Learned the hard way. --dpc
        script defer src="/assets/htmx.org-2.0.4.min.js" {}

        title { (title) }

        script {
            (PreEscaped(r#"
            function copyText(text, btn) {
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(text).then(function() {
                        showCopied(btn);
                    });
                } else {
                    var ta = document.createElement('textarea');
                    ta.value = text;
                    ta.style.position = 'fixed';
                    ta.style.opacity = '0';
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                    showCopied(btn);
                }
            }
            function showCopied(btn) {
                if (!btn) return;
                btn.classList.add('copied');
                var icon = btn.innerHTML;
                btn.innerHTML = '<i class="bi bi-check-lg"></i>';
                setTimeout(function() {
                    btn.innerHTML = icon;
                    btn.classList.remove('copied');
                }, 2000);
            }
            "#))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginInput {
    pub password: String,
}

pub fn single_card_layout(header: &str, content: Markup) -> Markup {
    card_layout("col-md-8 col-lg-5 narrow-container", header, content)
}

fn card_layout(col_class: &str, header: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (common_head("Fedimint"))
            }
            body class="d-flex align-items-center min-vh-100" {
                div class="container" {
                    div class="row justify-content-center" {
                        div class=(col_class) {
                            div class="card" {
                                div class="card-header dashboard-header" { (header) }
                                div class="card-body" {
                                    (content)
                                }
                            }
                        }
                    }
                }
                (connectivity_widget())
                script src="/assets/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
            }
        }
    }
}

/// Renders a readonly input with a copy-to-clipboard button using
/// Bootstrap's input-group pattern.
pub fn copiable_text(text: &str) -> Markup {
    html! {
        div class="input-group" {
            input type="text" class="form-control form-control-sm font-monospace"
                value=(text) readonly;
            button type="button" class="btn btn-outline-secondary"
                onclick=(format!("copyText('{}', this)", text)) {
                i class="bi bi-clipboard" {}
            }
        }
    }
}

pub fn login_form(error: Option<&str>) -> Markup {
    html! {
        form id="login-form" hx-post=(LOGIN_ROUTE) hx-target="#login-form" hx-swap="outerHTML" {
            div class="form-group mb-3" {
                input type="password" class="form-control" id="password" name="password" placeholder="Your Password" required autofocus;
            }
            @if let Some(error) = error {
                div class="alert alert-danger mb-3" { (error) }
            }
            button type="submit" class="btn btn-primary w-100 py-2" { "Continue" }
        }
    }
}

pub fn login_submit_response(
    auth: ApiAuth,
    auth_cookie_name: String,
    auth_cookie_value: String,
    jar: CookieJar,
    input: LoginInput,
) -> impl IntoResponse {
    if auth.verify(&input.password) {
        let mut cookie = Cookie::new(auth_cookie_name, auth_cookie_value);

        cookie.set_http_only(true);
        cookie.set_same_site(Some(SameSite::Lax));

        return (jar.add(cookie), [("HX-Redirect", "/")]).into_response();
    }

    Html(login_form(Some("The password is invalid")).into_string()).into_response()
}

pub fn dashboard_layout(content: Markup, version: &str) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                (common_head("Fedimint"))
            }
            body {
                div class="container" {
                    (content)

                    div class="text-center mt-4 mb-3" {
                        span class="text-muted" { "Version " (version) }
                    }
                }
                (connectivity_widget())
                script src="/assets/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
            }
        }
    }
}

/// Fixed-position div that loads the connectivity status fragment via htmx.
pub fn connectivity_widget() -> Markup {
    html! {
        div
            style="position: fixed; bottom: 1rem; right: 1rem; z-index: 1050;"
            hx-get=(CONNECTIVITY_CHECK_ROUTE)
            hx-trigger="load, every 30s"
            hx-swap="innerHTML"
        {}
    }
}

async fn check_tcp_connect(addr: SocketAddr) -> bool {
    timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// Handler that checks internet connectivity by attempting TCP connections
/// to well-known anycast IPs and returns an HTML fragment.
/// Manually checks auth cookie to avoid `UserAuth` extractor's redirect,
/// which would cause htmx to swap the entire login page into the widget.
pub async fn connectivity_check_handler<Api: Send + Sync + 'static>(
    State(state): State<UiState<Api>>,
    jar: CookieJar,
) -> Html<String> {
    // Check auth manually — return empty fragment if not authenticated.
    // In passwordless mode (`!requires_auth`), this widget is always shown.
    let authenticated = !state.requires_auth
        || jar
            .get(&state.auth_cookie_name)
            .is_some_and(|c| c.value() == state.auth_cookie_value);

    if !authenticated {
        return Html(String::new());
    }

    let check_1 = check_tcp_connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443));
    let check_2 = check_tcp_connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));

    let (r1, r2) = tokio::join!(check_1, check_2);
    let is_connected = r1 || r2;

    let markup = if is_connected {
        html! {
            span class="badge bg-success" style="font-size: 0.75rem;" {
                "Internet connection OK"
            }
        }
    } else {
        html! {
            span class="badge bg-danger" style="font-size: 0.75rem;" {
                "Internet connection unavailable"
            }
        }
    };

    Html(markup.into_string())
}
