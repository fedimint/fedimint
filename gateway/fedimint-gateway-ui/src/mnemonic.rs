use fedimint_gateway_common::MnemonicResponse;
use maud::{Markup, html};

use crate::DynGatewayApi;

pub async fn render<E>(api: &DynGatewayApi<E>) -> Markup
where
    E: std::fmt::Display,
{
    let result = api.handle_mnemonic_msg().await;

    match result {
        Ok(MnemonicResponse { mnemonic, .. }) => {
            html! {
                div class="card h-100" {
                    div class="card-header dashboard-header d-flex justify-content-between align-items-center" {
                        span { "Gateway Secret Phrase" }

                        // Toggle button
                        button
                            id="mnemonic-toggle-btn"
                            class="btn btn-sm btn-secondary"
                            type="button"
                            onclick="toggleMnemonicVisibility()"
                        {
                            "Show"
                        }
                    }

                    div class="card-body" {

                        // Ordered list with redacted words
                        ol id="mnemonic-list"
                           style="column-count: 2; column-gap: 2rem; font-size: 1.1rem; padding-left: 1.4rem;"
                        {
                            @for word in &mnemonic {
                                li class="mnemonic-word redacted" data-word=(word) {
                                    "••••••••"
                                }
                            }
                        }
                    }
                }

                script {
                    (maud::PreEscaped(r#"
                        function toggleMnemonicVisibility() {
                            const btn = document.getElementById("mnemonic-toggle-btn");
                            const redacted = document.querySelectorAll(".mnemonic-word");

                            const showing = btn.dataset.showing === "true";

                            redacted.forEach(el => {
                                if (showing) {
                                    // Hide → show redaction
                                    el.textContent = "••••••••";
                                } else {
                                    // Show → reveal actual word
                                    el.textContent = el.dataset.word;
                                }
                            });

                            btn.textContent = showing ? "Show" : "Hide";
                            btn.dataset.showing = (!showing).toString();
                        }
                    "#))
                }
            }
        }

        Err(e) => {
            html! {
                div class="card h-100 border-danger" {
                    div class="card-header dashboard-header bg-danger text-white" {
                        "Gateway Secret Phrase"
                    }
                    div class="card-body" {
                        div class="alert alert-danger mb-0" {
                            strong { "Failed to fetch mnemonic: " }
                            (e.to_string())
                        }
                    }
                }
            }
        }
    }
}
