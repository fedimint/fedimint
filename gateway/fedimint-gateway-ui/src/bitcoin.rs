use fedimint_gateway_common::{BlockchainInfo, ChainSource};
use maud::{Markup, html};

use crate::DynGatewayApi;

pub async fn render<E>(api: &DynGatewayApi<E>) -> Markup
where
    E: std::fmt::Display,
{
    let (blockchain_info, chain_source, network) = api.get_chain_source().await;

    // Determine block height and synced status
    let (block_height, status_badge) = match blockchain_info {
        BlockchainInfo::Connected {
            block_height,
            synced,
        } => {
            let badge = if synced {
                html! { span class="badge bg-success" { "🟢 Synced" } }
            } else {
                html! { span class="badge bg-warning" { "🟡 Syncing" } }
            };
            (block_height, badge)
        }
        BlockchainInfo::NotConnected => (
            0,
            html! { span class="badge bg-danger" { "❌ Not Connected" } },
        ),
    };

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
                        tr {
                            th { "Block Height" }
                            td { (block_height) }
                        }
                        tr {
                            th { "Status" }
                            td { (status_badge) }
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
