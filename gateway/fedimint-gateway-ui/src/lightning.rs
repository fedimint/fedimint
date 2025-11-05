use fedimint_gateway_common::{GatewayInfo, LightningMode};
use maud::{Markup, html};

use crate::DynGatewayApi;

pub async fn render<E>(gateway_info: &GatewayInfo, api: &DynGatewayApi<E>) -> Markup
where
    E: std::fmt::Display,
{
    // Try to load channels
    let channels_result = api.handle_list_channels_msg().await;

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Lightning" }
            div class="card-body" {

                // --- TABS ---
                ul class="nav nav-tabs" id="lightningTabs" role="tablist" {
                    li class="nav-item" role="presentation" {
                        button class="nav-link active"
                            id="connection-tab"
                            data-bs-toggle="tab"
                            data-bs-target="#connection-tab-pane"
                            type="button"
                            role="tab"
                        { "Connection Info" }
                    }
                    li class="nav-item" role="presentation" {
                        button class="nav-link"
                            id="channels-tab"
                            data-bs-toggle="tab"
                            data-bs-target="#channels-tab-pane"
                            type="button"
                            role="tab"
                        { "Channels" }
                    }
                }

                div class="tab-content mt-3" id="lightningTabsContent" {

                    // ──────────────────────────────────────────
                    //   TAB: CONNECTION INFO
                    // ──────────────────────────────────────────
                    div class="tab-pane fade show active"
                        id="connection-tab-pane"
                        role="tabpanel"
                        aria-labelledby="connection-tab" {

                        @match &gateway_info.lightning_mode {
                            LightningMode::Lnd { lnd_rpc_addr, lnd_tls_cert, lnd_macaroon } => {
                                div id="node-type" class="alert alert-info" {
                                    "Node Type: " strong { ("External LND") }
                                }
                                table class="table table-sm mb-0" {
                                    tbody {
                                        tr {
                                            th { "RPC Address" }
                                            td { (lnd_rpc_addr) }
                                        }
                                        tr {
                                            th { "TLS Cert" }
                                            td { (lnd_tls_cert) }
                                        }
                                        tr {
                                            th { "Macaroon" }
                                            td { (lnd_macaroon) }
                                        }
                                        @if let Some(alias) = &gateway_info.lightning_alias {
                                            tr {
                                                th { "Lightning Alias" }
                                                td { (alias) }
                                            }
                                        }
                                        @if let Some(pubkey) = &gateway_info.lightning_pub_key {
                                            tr {
                                                th { "Lightning Public Key" }
                                                td { (pubkey) }
                                            }
                                        }
                                    }
                                }
                            }
                            LightningMode::Ldk { lightning_port, alias: _ } => {
                                div id="node-type" class="alert alert-info" {
                                    "Node Type: " strong { ("Internal LDK") }
                                }
                                table class="table table-sm mb-0" {
                                    tbody {
                                        tr {
                                            th { "Port" }
                                            td { (lightning_port) }
                                        }
                                        @if let Some(alias) = &gateway_info.lightning_alias {
                                            tr {
                                                th { "Alias" }
                                                td { (alias) }
                                            }
                                        }
                                        @if let Some(pubkey) = &gateway_info.lightning_pub_key {
                                            tr {
                                                th { "Public Key" }
                                                td { (pubkey) }
                                            }
                                            @if let Some(host) = gateway_info.api.host_str() {
                                                tr {
                                                    th { "Connection String" }
                                                    td { (format!("{pubkey}@{host}:{lightning_port}")) }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ──────────────────────────────────────────
                    //   TAB: CHANNELS
                    // ──────────────────────────────────────────
                    div class="tab-pane fade"
                        id="channels-tab-pane"
                        role="tabpanel"
                        aria-labelledby="channels-tab" {

                        @match channels_result {
                            Err(err) => {
                                div class="alert alert-danger" {
                                    "Failed to load channels: " (err.to_string())
                                }
                            }
                            Ok(channels) => {
                                @if channels.is_empty() {
                                    div class="alert alert-info" {
                                        "No channels found."
                                    }
                                } @else {
                                    table class="table table-sm align-middle" {
                                        thead {
                                            tr {
                                                th { "Remote PubKey" }
                                                th { "Size (sats)" }
                                                th { "Active" }
                                                th { "Liquidity" }
                                            }
                                        }
                                        tbody {
                                            @for ch in channels {
                                                // Precompute
                                                @let size = ch.channel_size_sats.max(1);
                                                @let outbound_pct = (ch.outbound_liquidity_sats as f64 / size as f64) * 100.0;
                                                @let inbound_pct  = (ch.inbound_liquidity_sats  as f64 / size as f64) * 100.0;

                                                tr {
                                                    // Remote PubKey
                                                    td { (ch.remote_pubkey.to_string()) }

                                                    // Size
                                                    td { (ch.channel_size_sats) }

                                                    // Active?
                                                    td {
                                                        @if ch.is_active {
                                                            span class="badge bg-success" { "active" }
                                                        } @else {
                                                            span class="badge bg-secondary" { "inactive" }
                                                        }
                                                    }

                                                    // Liquidity visualization
                                                    td {
                                                        div style="width:240px;" {

                                                            // Bar (side-by-side)
                                                            div style="display:flex;height:10px;width:100%;border-radius:3px;overflow:hidden" {
                                                                // Outbound
                                                                div style=(format!(
                                                                    "background:#28a745;width:{:.2}%;",
                                                                    outbound_pct
                                                                )) {}

                                                                // Inbound
                                                                div style=(format!(
                                                                    "background:#0d6efd;width:{:.2}%;",
                                                                    inbound_pct
                                                                )) {}
                                                            }

                                                            // Legend
                                                            div style="font-size:0.75rem;display:flex;justify-content:space-between;margin-top:3px;" {
                                                                span {
                                                                    span style="display:inline-block;width:10px;height:10px;background:#28a745;margin-right:4px;border-radius:2px;" {}
                                                                    "Outbound"
                                                                }
                                                                span {
                                                                    span style="display:inline-block;width:10px;height:10px;background:#0d6efd;margin-right:4px;border-radius:2px;" {}
                                                                    "Inbound"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
