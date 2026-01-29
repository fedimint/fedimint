use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse};
use fedimint_gateway_common::MnemonicResponse;
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;

use crate::{DynGatewayApi, MNEMONIC_IFRAME_ROUTE};

/// Query parameters for the mnemonic iframe endpoint
#[derive(Default, Deserialize)]
pub struct MnemonicIframeQuery {
    pub reveal: Option<bool>,
}

/// Renders the mnemonic card with an isolated sandboxed iframe.
/// The mnemonic content is served from a separate endpoint and displayed
/// in an iframe with scripts disabled for security.
pub fn render() -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header d-flex justify-content-between align-items-center" {
                span { "Gateway Secret Phrase" }

                button
                    id="mnemonic-toggle-btn"
                    class="btn btn-sm btn-secondary"
                    type="button"
                    onclick="toggleMnemonicIframe()"
                {
                    "Show"
                }
            }

            div class="card-body" style="padding: 0;" {
                // Sandboxed iframe - empty sandbox attribute disables all scripts
                iframe
                    id="mnemonic-iframe"
                    src=(format!("{}?reveal=false", MNEMONIC_IFRAME_ROUTE))
                    sandbox=""
                    style="width: 100%; height: 280px; border: none; background: transparent;"
                    title="Gateway Secret Phrase"
                {}
            }
        }

        script {
            (PreEscaped(r#"
                function toggleMnemonicIframe() {
                    const btn = document.getElementById("mnemonic-toggle-btn");
                    const iframe = document.getElementById("mnemonic-iframe");
                    const showing = btn.dataset.showing === "true";

                    // Toggle by changing iframe src
                    const newReveal = !showing;
                    iframe.src = "/ui/mnemonic/iframe?reveal=" + newReveal;

                    btn.textContent = newReveal ? "Hide" : "Show";
                    btn.dataset.showing = newReveal.toString();
                }
            "#))
        }
    }
}

/// Renders the complete HTML document for the mnemonic iframe.
/// This document contains NO scripts - JavaScript is disabled via the sandbox
/// attribute.
fn render_iframe_content<E>(result: Result<MnemonicResponse, E>, reveal: bool) -> Markup
where
    E: std::fmt::Display,
{
    match result {
        Ok(MnemonicResponse { mnemonic, .. }) => {
            html! {
                (DOCTYPE)
                html {
                    head {
                        meta charset="utf-8";
                        meta name="viewport" content="width=device-width, initial-scale=1.0";
                        style {
                            (PreEscaped(r#"
                                body {
                                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                                    margin: 0;
                                    padding: 1rem;
                                    background-color: transparent;
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
                                .redacted {
                                    font-family: monospace;
                                    letter-spacing: 0.1em;
                                }
                            "#))
                        }
                    }
                    body {
                        ol {
                            @for word in &mnemonic {
                                @if reveal {
                                    li { (word) }
                                } @else {
                                    li class="redacted" { "••••••••" }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            html! {
                (DOCTYPE)
                html {
                    head {
                        meta charset="utf-8";
                        style {
                            (PreEscaped(r#"
                                body {
                                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                                    margin: 0;
                                    padding: 1rem;
                                    color: #dc3545;
                                }
                            "#))
                        }
                    }
                    body {
                        strong { "Failed to fetch mnemonic: " }
                        (e.to_string())
                    }
                }
            }
        }
    }
}

/// Handler for the mnemonic iframe endpoint.
/// Only allows requests from iframe context (Sec-Fetch-Dest: iframe) to prevent
/// malicious JavaScript from fetching the mnemonic directly.
pub async fn mnemonic_iframe_handler<E>(
    headers: HeaderMap,
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Query(query): Query<MnemonicIframeQuery>,
) -> impl IntoResponse
where
    E: std::fmt::Display + Send + Sync + 'static,
{
    // Only allow requests from iframe context to prevent fetch() attacks
    let fetch_dest = headers.get("Sec-Fetch-Dest").and_then(|v| v.to_str().ok());

    if fetch_dest != Some("iframe") {
        return (
            StatusCode::FORBIDDEN,
            "Mnemonic can only be viewed in the dashboard",
        )
            .into_response();
    }

    let reveal = query.reveal.unwrap_or(false);
    let result = state.api.handle_mnemonic_msg().await;
    let markup = render_iframe_content(result, reveal);

    (
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
        ],
        Html(markup.into_string()),
    )
        .into_response()
}
