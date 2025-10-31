use fedimint_gateway_common::{GatewayInfo, LightningMode};
use maud::{Markup, html};

pub fn render(gateway_info: &GatewayInfo) -> Markup {
    html!(
        div class="card h-100" {
            div class="card-header dashboard-header" { "Lightning" }
            div class="card-body" {
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
                    LightningMode::Ldk { lightning_port, alias: _alias } => {
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
        }
    )
}
