use fedimint_core::util::SafeUrl;
use fedimint_server_core::dashboard_ui::ServerBitcoinRpcStatus;
use maud::{Markup, html};

pub fn render(url: SafeUrl, status: &Option<ServerBitcoinRpcStatus>) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Bitcoin Rpc Connection" }
            div class="card-body" {
                div class="alert alert-info mb-3" {
                    (url.to_unsafe().to_string())
                }

                @if let Some(status) = status {
                    table class="table table-sm mb-0" {
                        tbody {
                            tr {
                                th { "Network" }
                                td { (format!("{:?}", status.network)) }
                            }
                            tr {
                                th { "Block Count" }
                                td { (status.block_count) }
                            }
                            tr {
                                th { "Fee Rate" }
                                td { (format!("{} sats/vB", status.fee_rate.sats_per_kvb / 1000)) }
                            }
                            @if let Some(sync) = status.sync_percentage {
                                tr {
                                    th { "Sync Progress" }
                                    td { (format!("{:.1}%", sync)) }
                                }
                            }
                        }
                    }
                } @else {
                    div class="alert alert-warning mb-0" {
                        "Failed to connect to bitcoin backend"
                    }
                }
            }
        }
    }
}
