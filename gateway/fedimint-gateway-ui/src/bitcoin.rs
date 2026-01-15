use fedimint_gateway_common::ChainSource;
use fedimint_logging::LOG_GATEWAY_UI;
use maud::{Markup, html};
use tracing::debug;

use crate::DynGatewayApi;

pub async fn render<E>(api: &DynGatewayApi<E>) -> Markup
where
    E: std::fmt::Display,
{
    debug!(target: LOG_GATEWAY_UI, "Getting bitcoin chain source...");
    let (chain_source, network) = api.get_chain_source().await;

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header d-flex justify-content-between align-items-center" {
                span { "Bitcoin Connection" }

                @if matches!(chain_source, ChainSource::Bitcoind { .. }) {
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
                        tr {
                            th { "Network" }
                            td { (network) }
                        }

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
