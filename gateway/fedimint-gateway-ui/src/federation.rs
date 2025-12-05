use std::fmt::Display;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse};
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_gateway_common::{
    DepositAddressPayload, FederationInfo, LeaveFedPayload, SetFeesPayload,
};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;
use qrcode::render::svg;

use crate::{
    DEPOSIT_ADDRESS_ROUTE, DynGatewayApi, SET_FEES_ROUTE, redirect_error, redirect_success,
};

pub fn scripts() -> Markup {
    html!(
        script {
            (PreEscaped(r#"
            function toggleFeesEdit(id) {
                const viewDiv = document.getElementById('fees-view-' + id);
                const editDiv = document.getElementById('fees-edit-' + id);
                if (viewDiv.style.display === 'none') {
                    viewDiv.style.display = '';
                    editDiv.style.display = 'none';
                } else {
                    viewDiv.style.display = 'none';
                    editDiv.style.display = '';
                }
            }

            function copyToClipboard(input) {
                input.select();
                document.execCommand('copy');
                const hint = input.nextElementSibling;
                hint.textContent = 'Copied!';
                setTimeout(() => hint.textContent = 'Click to copy', 2000);
            }
            "#))
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
        @let last_backup_str = fed.last_backup_time
            .map(time_ago)
            .unwrap_or("Never".to_string());


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
                        div class="alert alert-secondary py-1 px-2 small" {
                            "Last Backup: " strong { (last_backup_str) }
                        }

                        // --- TABS ---
                        ul class="nav nav-tabs" role="tablist" {
                            li class="nav-item" role="presentation" {
                                button class="nav-link active"
                                    id={(format!("fees-tab-{}", fed.federation_id))}
                                    data-bs-toggle="tab"
                                    data-bs-target={(format!("#fees-tab-pane-{}", fed.federation_id))}
                                    type="button"
                                    role="tab"
                                { "Fees" }
                            }
                            li class="nav-item" role="presentation" {
                                button class="nav-link"
                                    id={(format!("deposit-tab-{}", fed.federation_id))}
                                    data-bs-toggle="tab"
                                    data-bs-target={(format!("#deposit-tab-pane-{}", fed.federation_id))}
                                    type="button"
                                    role="tab"
                                { "Deposit" }
                            }
                        }

                        div class="tab-content mt-3" {

                            // ──────────────────────────────────────────
                            //   TAB: FEES
                            // ──────────────────────────────────────────
                            div class="tab-pane fade show active"
                                id={(format!("fees-tab-pane-{}", fed.federation_id))}
                                role="tabpanel"
                                aria-labelledby={(format!("fees-tab-{}", fed.federation_id))} {

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

                            // ──────────────────────────────────────────
                            //   TAB: DEPOSIT
                            // ──────────────────────────────────────────
                            div class="tab-pane fade"
                                id={(format!("deposit-tab-pane-{}", fed.federation_id))}
                                role="tabpanel"
                                aria-labelledby={(format!("deposit-tab-{}", fed.federation_id))} {

                                form hx-post=(DEPOSIT_ADDRESS_ROUTE)
                                     hx-target={(format!("#deposit-result-{}", fed.federation_id))}
                                     hx-swap="innerHTML"
                                {
                                    input type="hidden" name="federation_id" value=(fed.federation_id.to_string());
                                    button type="submit"
                                        class="btn btn-outline-primary btn-sm"
                                    {
                                        "New Deposit Address"
                                    }
                                }

                                div id=(format!("deposit-result-{}", fed.federation_id)) {}
                            }
                        }
                    }
                }
            }
        }
    )
}

fn time_ago(t: SystemTime) -> String {
    let now = fedimint_core::time::now();
    let diff = match now.duration_since(t) {
        Ok(d) => d,
        Err(_) => Duration::from_secs(0),
    };

    let secs = diff.as_secs();

    match secs {
        0..=59 => format!("{} seconds ago", secs),
        60..=3599 => format!("{} minutes ago", secs / 60),
        _ => format!("{} hours ago", secs / 3600),
    }
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
            Err(err) => {
                redirect_error(format!("Failed to leave federation: {err}")).into_response()
            }
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

pub async fn deposit_address_handler<E: Display>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<DepositAddressPayload>,
) -> impl IntoResponse {
    let markup = match state.api.handle_deposit_address_msg(payload).await {
        Ok(address) => {
            let code =
                QrCode::new(address.to_qr_uri().as_bytes()).expect("Failed to generate QR code");
            let qr_svg = code.render::<svg::Color>().build();

            html! {
                div class="card card-body bg-light d-flex flex-column align-items-center mt-2" {
                    span class="fw-bold mb-3" { "Deposit Address:" }

                    div class="d-flex flex-row align-items-center gap-3 flex-wrap" style="width: 100%;" {

                        // Copyable input + text
                        div class="d-flex flex-column flex-grow-1" style="min-width: 300px;" {
                            input type="text"
                                readonly
                                class="form-control mb-2"
                                style="text-align:left; font-family: monospace; font-size:1rem;"
                                value=(address)
                                onclick="copyToClipboard(this)"
                            {}
                            small class="text-muted" { "Click to copy" }
                        }

                        // QR code
                        div class="border rounded p-2 bg-white d-flex justify-content-center align-items-center"
                            style="width: 300px; height: 300px; min-width: 200px; min-height: 200px;"
                        {
                            (PreEscaped(format!(
                                r#"<svg style="width: 100%; height: 100%; display: block;">{}</svg>"#,
                                qr_svg.replace("width=", "data-width=").replace("height=", "data-height=")
                            )))
                        }
                    }
                }
            }
        }
        Err(err) => {
            html! {
                div class="alert alert-danger mt-2" {
                    "Failed to generate deposit address: " (err)
                }
            }
        }
    };
    Html(markup.into_string())
}
