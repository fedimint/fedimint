pub mod audit;
pub mod connection_status;
pub mod dashboard;
pub mod invite_code;
pub mod lnv2;
pub mod setup;
pub mod wallet;

use axum::response::{Html, IntoResponse, Redirect};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use fedimint_core::module::ApiAuth;
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct LoginInput {
    pub password: String,
}

// Common CSS styling shared by all layouts
pub fn common_styles() -> &'static str {
    r#"
    body {
        background-color: #f8f9fa;
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    .header-title {
        color: #0d6efd;
        margin-bottom: 2rem;
    }
    
    .card {
        border: none;
        box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    
    .card-body {
        padding: 1.25rem;
    }
    
    .card-header {
        background-color: #fff;
        border-bottom: 1px solid rgba(0, 0, 0, 0.125);
        padding: 1rem 1.25rem;
    }
    
    /* Form elements */
    .form-control {
        padding: 0.75rem;
    }
    
    .form-group {
        margin-bottom: 1rem;
    }
    
    .field-description {
        font-size: 0.875rem;
        color: #6c757d;
        margin-top: 0.25rem;
    }
    
    .button-container {
        margin-top: 2rem;
        text-align: center;
    }
    
    /* Alert and status messages */
    .error-message {
        color: #dc3545;
        margin-top: 1rem;
        font-weight: 500;
    }
    
    .alert-info {
        background-color: #e8f4f8;
        border-color: #bee5eb;
    }
    
    /* Connection and invite codes */
    .connection-code {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 0.25rem;
        padding: 1rem;
        overflow-x: auto;
        font-family: monospace;
        margin-bottom: 1rem;
        word-break: break-all;
        color: #000;
    }
    
    .connection-code code {
        color: #000 !important;
    }
    
    /* Button styling */
    .setup-btn {
        width: auto;
        min-width: 200px;
        max-width: 300px;
        padding: 0.5rem 1.5rem;
        margin: 0 auto;
    }
    
    /* Responsive adjustments */
    @media (min-width: 992px) {
        .narrow-container {
            max-width: 500px;
        }
    }
    
    @media (max-width: 768px) {
        .container {
            padding-left: 15px;
            padding-right: 15px;
        }
        
        .card-body {
            padding: 1rem;
        }
    }
    "#
}

pub(crate) fn login_layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { (title) }
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous";
                style {
                    (common_styles())
                }
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
                script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous" {}
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
    jar: CookieJar,
    input: LoginInput,
) -> impl IntoResponse {
    if auth.0 == input.password {
        let mut cookie = Cookie::new("guardian_api_auth", input.password);

        cookie.set_http_only(true);
        cookie.set_same_site(Some(SameSite::Lax));

        return (jar.add(cookie), Redirect::to("/")).into_response();
    }

    let content = html! {
        h2 class="mb-4 text-center" { "Guardian Login" }
        div class="alert alert-danger" role="alert" {
            "Invalid password. Please try again."
        }
        form method="post" action="/login" {
            div class="form-group mb-4" {
                label for="password" class="form-label" { "Guardian Password" }
                input type="password" class="form-control" id="password" name="password" placeholder="Your password" required;
            }
            div class="button-container" {
                button type="submit" class="btn btn-primary setup-btn" { "Log In" }
            }
        }
    };

    Html(login_layout("Login Failed", content).into_string()).into_response()
}

pub(crate) async fn check_auth(auth: ApiAuth, jar: &CookieJar) -> bool {
    let session_password = match jar.get("guardian_api_auth") {
        Some(cookie) => cookie.value().to_string(),
        None => return false,
    };

    auth.0 == session_password
}
