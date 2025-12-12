use std::fmt::Display;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse};
use bitcoin::Address;
use bitcoin::address::NetworkUnchecked;
use fedimint_core::config::FederationId;
use fedimint_core::{Amount, BitcoinAmountOrAll};
use fedimint_gateway_common::{
    DepositAddressPayload, FederationInfo, LeaveFedPayload, SetFeesPayload, WithdrawPayload,
    WithdrawPreviewPayload,
};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use fedimint_wallet_client::PegOutFees;
use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;
use qrcode::render::svg;

use crate::{
    DEPOSIT_ADDRESS_ROUTE, DynGatewayApi, SET_FEES_ROUTE, WITHDRAW_CONFIRM_ROUTE,
    WITHDRAW_PREVIEW_ROUTE, redirect_error, redirect_success,
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
                        div id=(format!("balance-{}", fed.federation_id)) class=(balance_class) {
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
                            li class="nav-item" role="presentation" {
                                button class="nav-link"
                                    id={(format!("withdraw-tab-{}", fed.federation_id))}
                                    data-bs-toggle="tab"
                                    data-bs-target={(format!("#withdraw-tab-pane-{}", fed.federation_id))}
                                    type="button"
                                    role="tab"
                                { "Withdraw" }
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

                            // ──────────────────────────────────────────
                            //   TAB: WITHDRAW
                            // ──────────────────────────────────────────
                            div class="tab-pane fade"
                                id={(format!("withdraw-tab-pane-{}", fed.federation_id))}
                                role="tabpanel"
                                aria-labelledby={(format!("withdraw-tab-{}", fed.federation_id))} {

                                form hx-post=(WITHDRAW_PREVIEW_ROUTE)
                                     hx-target={(format!("#withdraw-result-{}", fed.federation_id))}
                                     hx-swap="innerHTML"
                                     class="mt-3"
                                     id=(format!("withdraw-form-{}", fed.federation_id))
                                {
                                    input type="hidden" name="federation_id" value=(fed.federation_id.to_string());

                                    div class="mb-3" {
                                        label class="form-label" for=(format!("withdraw-amount-{}", fed.federation_id)) { "Amount (sats or 'all')" }
                                        input type="text"
                                            class="form-control"
                                            id=(format!("withdraw-amount-{}", fed.federation_id))
                                            name="amount"
                                            placeholder="e.g. 100000 or all"
                                            required;
                                    }

                                    div class="mb-3" {
                                        label class="form-label" for=(format!("withdraw-address-{}", fed.federation_id)) { "Bitcoin Address" }
                                        input type="text"
                                            class="form-control"
                                            id=(format!("withdraw-address-{}", fed.federation_id))
                                            name="address"
                                            placeholder="bc1q..."
                                            required;
                                    }

                                    button type="submit" class="btn btn-primary" { "Preview" }
                                }

                                div id=(format!("withdraw-result-{}", fed.federation_id)) class="mt-3" {}
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

/// Preview handler for two-step withdrawal flow - shows fee breakdown before
/// confirmation
pub async fn withdraw_preview_handler<E: Display>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<WithdrawPreviewPayload>,
) -> impl IntoResponse {
    let federation_id = payload.federation_id;
    let is_max = matches!(payload.amount, BitcoinAmountOrAll::All);

    let markup = match state.api.handle_withdraw_preview_msg(payload).await {
        Ok(response) => {
            let amount_label = if is_max {
                format!("{} sats (max)", response.withdraw_amount.sats_round_down())
            } else {
                format!("{} sats", response.withdraw_amount.sats_round_down())
            };

            html! {
                div class="card" {
                    div class="card-body" {
                        h6 class="card-title" { "Withdrawal Preview" }

                        table class="table table-sm" {
                            tbody {
                                tr {
                                    td { "Amount" }
                                    td { (amount_label) }
                                }
                                tr {
                                    td { "Address" }
                                    td class="text-break" style="font-family: monospace; font-size: 0.85em;" {
                                        (response.address.clone())
                                    }
                                }
                                tr {
                                    td { "Fee Rate" }
                                    td { (format!("{} sats/kvB", response.peg_out_fees.fee_rate.sats_per_kvb)) }
                                }
                                tr {
                                    td { "Transaction Size" }
                                    td { (format!("{} weight units", response.peg_out_fees.total_weight)) }
                                }
                                tr {
                                    td { "Peg-out Fee" }
                                    td { (format!("{} sats", response.peg_out_fees.amount().to_sat())) }
                                }
                                @if let Some(mint_fee) = response.mint_fees {
                                    tr {
                                        td { "Mint Fee (est.)" }
                                        td { (format!("~{} sats", mint_fee.sats_round_down())) }
                                    }
                                }
                                tr {
                                    td { strong { "Total Deducted" } }
                                    td { strong { (format!("{} sats", response.total_cost.sats_round_down())) } }
                                }
                            }
                        }

                        div class="d-flex gap-2 mt-3" {
                            // Confirm form with hidden fields
                            form hx-post=(WITHDRAW_CONFIRM_ROUTE)
                                 hx-target=(format!("#withdraw-result-{}", federation_id))
                                 hx-swap="innerHTML"
                            {
                                input type="hidden" name="federation_id" value=(federation_id.to_string());
                                input type="hidden" name="amount" value=(response.withdraw_amount.sats_round_down().to_string());
                                input type="hidden" name="address" value=(response.address);
                                input type="hidden" name="fee_rate_sats_per_kvb" value=(response.peg_out_fees.fee_rate.sats_per_kvb.to_string());
                                input type="hidden" name="total_weight" value=(response.peg_out_fees.total_weight.to_string());

                                button type="submit" class="btn btn-success" { "Confirm Withdrawal" }
                            }

                            // Cancel button - clears the result area
                            button type="button"
                                   class="btn btn-outline-secondary"
                                   onclick=(format!("document.getElementById('withdraw-result-{}').innerHTML = ''", federation_id))
                            { "Cancel" }
                        }
                    }
                }
            }
        }
        Err(err) => {
            html! {
                div class="alert alert-danger" {
                    "Error: " (err.to_string())
                }
            }
        }
    };
    Html(markup.into_string())
}

/// Payload for withdraw confirmation from the UI
#[derive(Debug, serde::Deserialize)]
pub struct WithdrawConfirmPayload {
    pub federation_id: FederationId,
    pub amount: u64,
    pub address: String,
    pub fee_rate_sats_per_kvb: u64,
    pub total_weight: u64,
}

/// Confirm handler for two-step withdrawal flow - executes withdrawal with
/// quoted fees
pub async fn withdraw_confirm_handler<E: Display>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<WithdrawConfirmPayload>,
) -> impl IntoResponse {
    let federation_id = payload.federation_id;

    // Parse the address - it should already be validated from the preview step
    let address: Address<NetworkUnchecked> = match payload.address.parse() {
        Ok(addr) => addr,
        Err(err) => {
            return Html(
                html! {
                    div class="alert alert-danger" {
                        "Error parsing address: " (err.to_string())
                    }
                }
                .into_string(),
            );
        }
    };

    // Build the WithdrawPayload with the quoted fees
    let withdraw_payload = WithdrawPayload {
        federation_id,
        amount: BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(payload.amount)),
        address,
        quoted_fees: Some(PegOutFees::new(
            payload.fee_rate_sats_per_kvb,
            payload.total_weight,
        )),
    };

    let markup = match state.api.handle_withdraw_msg(withdraw_payload).await {
        Ok(response) => {
            // Fetch updated balance for the out-of-band swap
            let updated_balance = state
                .api
                .handle_get_balances_msg()
                .await
                .ok()
                .and_then(|balances| {
                    balances
                        .ecash_balances
                        .into_iter()
                        .find(|b| b.federation_id == federation_id)
                        .map(|b| b.ecash_balance_msats)
                })
                .unwrap_or(Amount::ZERO);

            let balance_class = if updated_balance == Amount::ZERO {
                "alert alert-danger"
            } else {
                "alert alert-success"
            };

            html! {
                // Success message (swaps into result div)
                div class="alert alert-success" {
                    p { strong { "Withdrawal successful!" } }
                    p { "Transaction ID: " code { (response.txid) } }
                    p { "Peg-out Fee: " (format!("{} sats", response.fees.amount().to_sat())) }
                }

                // Out-of-band swap to update balance banner
                div id=(format!("balance-{}", federation_id))
                    class=(balance_class)
                    hx-swap-oob="true"
                {
                    "Balance: " strong { (updated_balance) }
                }
            }
        }
        Err(err) => {
            html! {
                div class="alert alert-danger" {
                    "Error: " (err.to_string())
                }
            }
        }
    };
    Html(markup.into_string())
}
