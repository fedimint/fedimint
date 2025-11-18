use std::fmt::Display;
use std::str::FromStr;

use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_gateway_common::{FederationInfo, LeaveFedPayload};
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{ROOT_ROUTE, UiState, dashboard_layout};
use maud::{Markup, html};

use crate::DynGatewayApi;

pub fn render(fed: &FederationInfo) -> Markup {
    html!(
        @let bal = fed.balance_msat;
        @let balance_class = if bal == Amount::ZERO {
            "alert alert-danger"
        } else {
            "alert alert-success"
        };

        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card h-100" {
                    div class="card-header dashboard-header d-flex justify-content-between align-items-center" {
                        div {
                            (fed.federation_name.clone().unwrap_or("Unnamed Federation".to_string()))
                        }

                        form method="post" action={(format!("/ui/federations/{}/leave", fed.federation_id))} {
                            button type="submit"
                                class="btn btn-outline-danger btn-sm"
                                title="Leave Federation" { "📤" }
                        }
                    }
                    div class="card-body" {
                        div id="balance" class=(balance_class) {
                            "Balance: " strong { (fed.balance_msat) }
                        }
                        table class="table table-sm mb-0" {
                            tbody {
                                tr {
                                    th { "Federation ID" }
                                    td { (fed.federation_id) }
                                }
                                tr {
                                    th { "Lightning Fee" }
                                    td {
                                        table class="table table-sm mb-0" {
                                            tbody {
                                                tr {
                                                    th { "Base Fee" }
                                                    td { (fed.config.lightning_fee.base) }
                                                }
                                                tr {
                                                    th { "Parts Per Million" }
                                                    td { (fed.config.lightning_fee.parts_per_million) }
                                                }
                                            }
                                        }
                                    }
                                }
                                tr {
                                    th { "Transaction Fee" }
                                    td {
                                        table class="table table-sm mb-0" {
                                            tbody {
                                                tr {
                                                    th { "Base Fee" }
                                                    td { (fed.config.transaction_fee.base) }
                                                }
                                                tr {
                                                    th { "Parts Per Million" }
                                                    td { (fed.config.transaction_fee.parts_per_million) }
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

pub async fn leave_federation_handler<E: Display>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    Path(id): Path<String>,
    _auth: UserAuth,
) -> impl IntoResponse {
    let federation_id = FederationId::from_str(&id);
    if let Ok(federation_id) = federation_id {
        match state
            .api
            .handle_leave_federation(LeaveFedPayload { federation_id })
            .await
        {
            Ok(_) => {
                // Redirect back to dashboard after success
                Redirect::to(ROOT_ROUTE).into_response()
            }
            Err(err) => {
                let content = html! {
                    div class="alert alert-danger mt-4" {
                        strong { "Failed to leave federation: " }
                        (err.to_string())
                    }
                };
                Html(dashboard_layout(content, "Fedimint Gateway UI", None).into_string())
                    .into_response()
            }
        }
    } else {
        let content = html! {
            div class="alert alert-danger mt-4" {
                strong { "Failed to leave federation: Invalid federation id" }
            }
        };
        Html(dashboard_layout(content, "Fedimint Gateway UI", None).into_string()).into_response()
    }
}
