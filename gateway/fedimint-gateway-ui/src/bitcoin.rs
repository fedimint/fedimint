use fedimint_gateway_common::ChainSource;
use maud::{Markup, html};

use crate::DynGatewayApi;

pub fn render<E>(api: &DynGatewayApi<E>) -> Markup
where
    E: std::fmt::Display,
{
    let chain_source = api.get_chain_source();

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header d-flex justify-content-between align-items-center" {
                span { "Bitcoin Connection" }

                @if matches!(chain_source, ChainSource::Bitcoind { .. }) {
                    // Show/hide button for password
                    button
                        id="btc-password-toggle-btn"
                        class="btn btn-sm btn-secondary"
                        type="button"
                        onclick="toggleBtcPassword()"
                    {
                        "Show"
                    }
                }
            }

            div class="card-body" {
                table class="table table-sm mb-0" {
                    tbody {
                        @match &chain_source {
                            ChainSource::Bitcoind { username, password, server_url } => {
                                tr {
                                    th { "Type" }
                                    td { "Bitcoind" }
                                }
                                tr {
                                    th { "Server URL" }
                                    td { (server_url) }
                                }
                                tr {
                                    th { "Username" }
                                    td { (username) }
                                }
                                tr {
                                    th { "Password" }
                                    td id="btc-password" data-password=(password) { "••••••" }
                                }
                            },
                            ChainSource::Esplora { server_url } => {
                                tr {
                                    th { "Type" }
                                    td { "Esplora" }
                                }
                                tr {
                                    th { "Server URL" }
                                    td { (server_url) }
                                }
                            }
                        }
                    }
                }
            }
        }

        @if matches!(chain_source, ChainSource::Bitcoind { .. }) {
            // Inline script for password toggle
            script {
                (maud::PreEscaped(r#"
                    function toggleBtcPassword() {
                        const btn = document.getElementById("btc-password-toggle-btn");
                        const pwdEl = document.getElementById("btc-password");
                        const showing = btn.dataset.showing === "true";

                        if (showing) {
                            pwdEl.textContent = "••••••";
                        } else {
                            pwdEl.textContent = pwdEl.dataset.password;
                        }

                        btn.textContent = showing ? "Show" : "Hide";
                        btn.dataset.showing = (!showing).toString();
                    }
                "#))
            }
        }
    }
}
