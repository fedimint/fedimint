use fedimint_gateway_common::GatewayInfo;
use maud::{Markup, html};

pub fn render(gateway_info: &GatewayInfo) -> Markup {
    html!(
        div class="card h-100" {
            div class="card-header dashboard-header" { "Gateway Network Information" }

            div class="card-body" {

                div id="status" class="alert alert-info" {
                    "Status: " strong { (gateway_info.gateway_state.clone()) }
                }

                @if gateway_info.registrations.is_empty() {
                    div class="alert alert-secondary" {
                        "No registrations found."
                    }
                } @else {
                    table class="table table-sm" {
                        thead {
                            tr {
                                th { "Protocol" }
                                th { "Details" }
                            }
                        }
                        tbody {
                            @for (protocol, (url, pubkey)) in &gateway_info.registrations {
                                tr {
                                    td class="align-middle fw-bold" {
                                        (format!("{:?}", protocol))
                                    }

                                    td {
                                        table class="table table-borderless table-sm mb-0 w-100" {
                                            tbody {
                                                tr {
                                                    td class="fw-semibold pe-2 align-top" {
                                                        "URL:"
                                                    }
                                                    td class="text-break small" {
                                                        (url.to_string())
                                                    }
                                                }
                                                tr {
                                                    td class="fw-semibold pe-2 align-top" {
                                                        "ID:"
                                                    }
                                                    td class="text-break font-monospace small" {
                                                        (pubkey.to_string())
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
    )
}
