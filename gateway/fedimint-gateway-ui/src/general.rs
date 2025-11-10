use fedimint_gateway_common::GatewayInfo;
use maud::{Markup, html};

pub fn render(gateway_info: &GatewayInfo) -> Markup {
    html!(
        div class="card h-100" {
            div class="card-header dashboard-header" { "Gateway Information" }
            div class="card-body" {
                div id="status" class="alert alert-info" {
                    "Status: " strong { (gateway_info.gateway_state.clone()) }
                }

                table class="table table-sm mb-0" {
                    tbody {
                        tr {
                            th { "Gateway ID" }
                            td { (gateway_info.gateway_id.to_string()) }
                        }
                        tr {
                            th { "API Endpoint" }
                            td { (gateway_info.api.to_string()) }
                        }
                        tr {
                            th { "Iroh API" }
                            td { (gateway_info.iroh_api.to_string()) }
                        }
                    }
                }
            }
        }
    )
}
