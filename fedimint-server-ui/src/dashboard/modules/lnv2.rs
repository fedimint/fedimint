use axum::extract::{Form, State};
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::cookie::CookieJar;
use fedimint_core::util::SafeUrl;
use fedimint_server_core::dashboard_ui::{DashboardApiModuleExt, DynDashboardApi};
use maud::{Markup, html};

use crate::{AuthState, check_auth};

// Form for gateway management
#[derive(serde::Deserialize)]
pub struct GatewayForm {
    pub gateway_url: SafeUrl,
}

// Function to render the Lightning V2 module UI section
pub async fn render(lightning: &fedimint_lnv2_server::Lightning) -> Markup {
    let gateways = lightning.gateways_ui().await;
    let consensus_block_count = lightning.consensus_block_count_ui().await;
    let consensus_unix_time = lightning.consensus_unix_time_ui().await;
    let formatted_unix_time = chrono::DateTime::from_timestamp(consensus_unix_time as i64, 0)
        .map(|dt| dt.to_rfc2822())
        .unwrap_or("Invalid time".to_string());

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Lightning V2" }
            div class="card-body" {
                // Consensus status information
                div class="mb-4" {
                    table
                        class="table"
                        id="lnv2-module-timers" hx-swap-oob=(true)
                    {
                        tr {
                            th { "Consensus Block Count" }
                            td { (consensus_block_count) }
                        }
                        tr {
                            th { "Consensus Unix Time" }
                            td { (formatted_unix_time) }
                        }
                    }
                }

                // Gateway management
                div {
                    div class="row" {
                        // Left tile - Gateway list or message
                        div class="col-lg-6 pe-lg-4 position-relative" {
                            div class="h-100" {
                                @if gateways.is_empty() {
                                    div class="text-center p-4" {
                                        p { "You need a Lightning gateway to connect to your federation and then add its URL here in the dashboard to enable V2 Lightning payments for your users. You can either run your own gateway or reach out to the Fedimint team on " a href="https://chat.fedimint.org/" { "Discord" } " - we are running our own gateway and are happy to get you started." }
                                    }
                                } @else {
                                    div class="table-responsive" {
                                        table class="table table-hover" {
                                            tbody {
                                                @for gateway in &gateways {
                                                    tr {
                                                        td { (gateway.to_string()) }
                                                        td class="text-end" {
                                                            form action="/lnv2_gateway_remove" method="post" style="display: inline;" {
                                                                input type="hidden" name="gateway_url" value=(gateway.to_string());
                                                                button type="submit" class="btn btn-sm btn-danger" {
                                                                    "Remove"
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
                            // Add vertical divider
                            div class="position-absolute end-0 top-0 bottom-0 d-none d-lg-block" style="width: 1px; background-color: #dee2e6;" {}
                        }

                        // Right tile - Add gateway form
                        div class="col-lg-6 ps-lg-4" {
                            div class="d-flex flex-column align-items-center h-100" {
                                form action="/lnv2_gateway_add" method="post" class="w-100" style="max-width: 400px;" {
                                    div class="mb-3" {
                                        input
                                            type="url"
                                            class="form-control"
                                            id="gateway-url"
                                            name="gateway_url"
                                            placeholder="Enter gateway URL"
                                            required;
                                    }
                                    div class="text-muted mb-3 text-center" style="font-size: 0.875em;" {
                                        "Please enter a valid URL starting with http:// or https://"
                                    }
                                    div class="text-center" {
                                        button type="submit" class="btn btn-primary" style="min-width: 150px;" {
                                            "Add Gateway"
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

// Handler for adding a new gateway
pub async fn add_gateway(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(form): Form<GatewayForm>,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    state
        .api
        .get_module::<fedimint_lnv2_server::Lightning>()
        .expect("Route only mounted when Lightning V2 module exists")
        .add_gateway_ui(form.gateway_url)
        .await;

    Redirect::to("/").into_response()
}

// Handler for removing a gateway
pub async fn remove_gateway(
    State(state): State<AuthState<DynDashboardApi>>,
    jar: CookieJar,
    Form(form): Form<GatewayForm>,
) -> impl IntoResponse {
    if !check_auth(&state.auth_cookie_name, &state.auth_cookie_value, &jar).await {
        return Redirect::to("/login").into_response();
    }

    state
        .api
        .get_module::<fedimint_lnv2_server::Lightning>()
        .expect("Route only mounted when Lightning V2 module exists")
        .remove_gateway_ui(form.gateway_url)
        .await;

    Redirect::to("/").into_response()
}
