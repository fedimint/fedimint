use axum::Form;
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;

use crate::{DynGatewayApi, MNEMONIC_IFRAME_ROUTE};

/// Form data for revealing the mnemonic
#[derive(Deserialize)]
pub struct RevealMnemonicForm {
    pub password: String,
}

/// Renders the mnemonic card with password-protected reveal.
/// The mnemonic is only displayed after re-authentication, and the form
/// submits directly to a sandboxed iframe so the mnemonic never passes
/// through parent page JavaScript.
pub fn render() -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" {
                span { "Gateway Secret Phrase" }
            }

            div class="card-body" {
                // Password form that submits directly to the iframe
                form
                    id="mnemonic-reveal-form"
                    method="post"
                    action=(MNEMONIC_IFRAME_ROUTE)
                    target="mnemonic-iframe"
                    class="mb-3"
                {
                    div class="input-group" {
                        input
                            type="password"
                            name="password"
                            class="form-control"
                            placeholder="Enter password to reveal"
                            autocomplete="current-password"
                            required;
                        button type="submit" class="btn btn-secondary" {
                            "Show"
                        }
                        button
                            type="button"
                            class="btn btn-outline-secondary"
                            onclick="hideMnemonic()"
                        {
                            "Hide"
                        }
                    }
                }

                // Sandboxed iframe - form submits here, scripts disabled
                // The sandbox attribute with allow-forms is needed to accept form submissions
                // but scripts remain disabled
                iframe
                    name="mnemonic-iframe"
                    id="mnemonic-iframe"
                    src=(MNEMONIC_IFRAME_ROUTE)
                    sandbox=""
                    style="width: 100%; height: 240px; border: 1px solid #dee2e6; border-radius: 0.375rem; background: #fff;"
                    title="Gateway Secret Phrase"
                {}
            }
        }

        script {
            (PreEscaped(r#"
                function hideMnemonic() {
                    document.getElementById("mnemonic-iframe").src = "/ui/mnemonic/iframe";
                    document.querySelector("input[name=password]").value = "";
                }
            "#))
        }
    }
}

/// Common styles for iframe content
fn iframe_styles() -> Markup {
    html! {
        style {
            (PreEscaped(r#"
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    margin: 0;
                    padding: 1rem;
                    background-color: #fff;
                }
                ol {
                    column-count: 2;
                    column-gap: 2rem;
                    font-size: 1.1rem;
                    padding-left: 1.4rem;
                    margin: 0;
                }
                li {
                    margin-bottom: 0.25rem;
                }
                .placeholder {
                    color: #6c757d;
                    font-style: italic;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100%;
                    min-height: 200px;
                }
                .error {
                    color: #dc3545;
                    padding: 0.75rem;
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 0.375rem;
                }
                .warning {
                    color: #856404;
                    padding: 0.75rem;
                    background-color: #fff3cd;
                    border: 1px solid #ffeeba;
                    border-radius: 0.375rem;
                    margin-bottom: 1rem;
                    font-size: 0.9rem;
                }
            "#))
        }
    }
}

/// Renders the initial iframe content (placeholder prompting for password)
fn render_iframe_initial() -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                (iframe_styles())
            }
            body {
                div class="placeholder" {
                    "Enter your password to reveal the secret phrase"
                }
            }
        }
    }
}

/// Renders the iframe content with the revealed mnemonic
fn render_iframe_revealed(mnemonic: &[String]) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                (iframe_styles())
            }
            body {
                div class="warning" {
                    "⚠ Never share these words with anyone. Store them securely offline."
                }
                ol {
                    @for word in mnemonic {
                        li { (word) }
                    }
                }
            }
        }
    }
}

/// Renders the iframe content with an error message
fn render_iframe_error(message: &str) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                (iframe_styles())
            }
            body {
                div class="error" {
                    strong { "Error: " }
                    (message)
                }
            }
        }
    }
}

/// Security headers for iframe responses
fn iframe_security_headers() -> [(header::HeaderName, &'static str); 4] {
    [
        (
            header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, private",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "SAMEORIGIN"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'",
        ),
    ]
}

/// Handler for the initial iframe content (GET request).
/// Returns a placeholder prompting the user to enter their password.
pub async fn mnemonic_iframe_handler<E>(
    _state: State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
) -> impl IntoResponse
where
    E: std::fmt::Display + Send + Sync + 'static,
{
    let markup = render_iframe_initial();
    (iframe_security_headers(), Html(markup.into_string())).into_response()
}

/// Handler for revealing the mnemonic (POST request with password).
/// Verifies the password and returns the mnemonic if valid.
pub async fn mnemonic_reveal_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(form): Form<RevealMnemonicForm>,
) -> impl IntoResponse
where
    E: std::fmt::Display + Send + Sync + 'static,
{
    // Verify password
    let password_valid =
        bcrypt::verify(&form.password, &state.api.get_password_hash()).unwrap_or(false);

    if !password_valid {
        let markup = render_iframe_error("Invalid password");
        return (iframe_security_headers(), Html(markup.into_string())).into_response();
    }

    // Password valid, fetch and display mnemonic
    match state.api.handle_mnemonic_msg().await {
        Ok(response) => {
            let markup = render_iframe_revealed(&response.mnemonic);
            (iframe_security_headers(), Html(markup.into_string())).into_response()
        }
        Err(e) => {
            let markup = render_iframe_error(&format!("Failed to fetch mnemonic: {e}"));
            (iframe_security_headers(), Html(markup.into_string())).into_response()
        }
    }
}
