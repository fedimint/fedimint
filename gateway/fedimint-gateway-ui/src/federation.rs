use std::fmt::Display;
use std::str::FromStr;

use axum::Form;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_gateway_common::{FederationInfo, LeaveFedPayload, SetFeesPayload};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{Markup, html};

use crate::{DynGatewayApi, SET_FEES_ROUTE, redirect_error, redirect_success};

pub fn scripts() -> Markup {
    html!(
        script {
            "function toggleFeesEdit(id) { \
                const view = document.getElementById('fees-view-' + id); \
                const edit = document.getElementById('fees-edit-' + id); \
                if (view.style.display === 'none') { \
                    view.style.display = 'block'; \
                    edit.style.display = 'none'; \
                } else { \
                    view.style.display = 'none'; \
                    edit.style.display = 'block'; \
                } \
            }"
        }
    )
}

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
                        // READ-ONLY VERSION
                        div id={(format!("fees-view-{}", fed.federation_id))} {
                            table class="table table-sm mb-2" {
                                tbody {
                                    tr {
                                        th { "Lightning Base Fee" }
                                        td { (fed.config.lightning_fee.base) }
                                    }
                                    tr {
                                        th { "Lightning PPM" }
                                        td { (fed.config.lightning_fee.parts_per_million) }
                                    }
                                    tr {
                                        th { "Transaction Base Fee" }
                                        td { (fed.config.transaction_fee.base) }
                                    }
                                    tr {
                                        th { "Transaction PPM" }
                                        td { (fed.config.transaction_fee.parts_per_million) }
                                    }
                                }
                            }

                            button
                                class="btn btn-sm btn-outline-primary"
                                type="button"
                                onclick={(format!("toggleFeesEdit('{}')", fed.federation_id))}
                            {
                                "Edit Fees"
                            }
                        }

                        // EDIT FORM (HIDDEN INITIALLY)
                        div id={(format!("fees-edit-{}", fed.federation_id))} style="display: none;" {
                            form
                                method="post"
                                action={(SET_FEES_ROUTE)}
                            {
                                input type="hidden" name="federation_id" value=(fed.federation_id.to_string());
                                table class="table table-sm mb-2" {
                                    tbody {
                                        tr {
                                            th { "Lightning Base Fee" }
                                            td {
                                                input type="number"
                                                    class="form-control form-control-sm"
                                                    name="lightning_base"
                                                    value=(fed.config.lightning_fee.base.msats);
                                            }
                                        }
                                        tr {
                                            th { "Lightning PPM" }
                                            td {
                                                input type="number"
                                                    class="form-control form-control-sm"
                                                    name="lightning_parts_per_million"
                                                    value=(fed.config.lightning_fee.parts_per_million);
                                            }
                                        }
                                        tr {
                                            th { "Transaction Base Fee" }
                                            td {
                                                input type="number"
                                                    class="form-control form-control-sm"
                                                    name="transaction_base"
                                                    value=(fed.config.transaction_fee.base.msats);
                                            }
                                        }
                                        tr {
                                            th { "Transaction PPM" }
                                            td {
                                                input type="number"
                                                    class="form-control form-control-sm"
                                                    name="transaction_parts_per_million"
                                                    value=(fed.config.transaction_fee.parts_per_million);
                                            }
                                        }
                                    }
                                }

                                button type="submit" class="btn btn-sm btn-primary me-2" { "Save Fees" }
                                button
                                    type="button"
                                    class="btn btn-sm btn-secondary"
                                    onclick={(format!("toggleFeesEdit('{}')", fed.federation_id))}
                                {
                                    "Cancel"
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
            Ok(info) => {
                // Redirect back to dashboard after success
                redirect_success(format!(
                    "Successfully left {}",
                    info.federation_name
                        .unwrap_or("Unnamed Federation".to_string())
                ))
                .into_response()
            }
            Err(err) => redirect_error(format!("Failed to leave federation: {}", err.to_string()))
                .into_response(),
        }
    } else {
        redirect_error("Failed to leave federation: Invalid federation id".to_string())
            .into_response()
    }
}

pub async fn set_fees_handler<E: Display>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<SetFeesPayload>,
) -> impl IntoResponse {
    tracing::info!("Received fees payload: {:?}", payload);

    match state.api.handle_set_fees_msg(payload).await {
        Ok(_) => redirect_success("Successfully set fees".to_string()).into_response(),
        Err(err) => redirect_error(format!("Failed to update fees: {err}")).into_response(),
    }
}
