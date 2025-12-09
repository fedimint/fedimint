use std::collections::HashMap;
use std::fmt::Display;
use std::time::{Duration, UNIX_EPOCH};

use axum::Form;
use axum::extract::{Query, State};
use axum::response::Html;
use chrono::offset::LocalResult;
use chrono::{TimeZone, Utc};
use fedimint_core::bitcoin::Network;
use fedimint_core::time::now;
use fedimint_gateway_common::{
    ChannelInfo, CloseChannelsWithPeerRequest, CreateInvoiceForOperatorPayload, GatewayBalances,
    GatewayInfo, LightningInfo, LightningMode, ListTransactionsPayload, ListTransactionsResponse,
    OpenChannelRequest, PayInvoiceForOperatorPayload, PaymentStatus, SendOnchainRequest,
};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{Markup, PreEscaped, html};
use qrcode::QrCode;
use qrcode::render::svg;

use crate::{
    CHANNEL_FRAGMENT_ROUTE, CLOSE_CHANNEL_ROUTE, CREATE_BOLT11_INVOICE_ROUTE, DynGatewayApi,
    LN_ONCHAIN_ADDRESS_ROUTE, OPEN_CHANNEL_ROUTE, PAY_BOLT11_INVOICE_ROUTE,
    PAYMENTS_FRAGMENT_ROUTE, SEND_ONCHAIN_ROUTE, TRANSACTIONS_FRAGMENT_ROUTE,
    WALLET_FRAGMENT_ROUTE,
};

pub async fn render<E>(gateway_info: &GatewayInfo, api: &DynGatewayApi<E>) -> Markup
where
    E: std::fmt::Display,
{
    // Try to load channels
    let channels_result = api.handle_list_channels_msg().await;

    // Extract LightningInfo status
    let (block_height, status_badge, network, alias, pubkey) = match &gateway_info.lightning_info {
        LightningInfo::Connected {
            network,
            block_height,
            synced_to_chain,
            alias,
            public_key,
        } => {
            let badge = if *synced_to_chain {
                html! { span class="badge bg-success" { "🟢 Synced" } }
            } else {
                html! { span class="badge bg-warning" { "🟡 Syncing" } }
            };
            (
                *block_height,
                badge,
                *network,
                Some(alias.clone()),
                Some(*public_key),
            )
        }
        LightningInfo::NotConnected => (
            0,
            html! { span class="badge bg-danger" { "❌ Not Connected" } },
            Network::Bitcoin,
            None,
            None,
        ),
    };

    let is_lnd = matches!(api.lightning_mode(), LightningMode::Lnd { .. });
    let balances_result = api.handle_get_balances_msg().await;
    let now = now();
    let start = now
        .checked_sub(Duration::from_secs(60 * 60 * 24))
        .expect("Cannot be negative");
    let start_secs = start
        .duration_since(UNIX_EPOCH)
        .expect("Cannot be before epoch")
        .as_secs();
    let end = now;
    let end_secs = end
        .duration_since(UNIX_EPOCH)
        .expect("Cannot be before epoch")
        .as_secs();
    let transactions_result = api
        .handle_list_transactions_msg(ListTransactionsPayload {
            start_secs,
            end_secs,
        })
        .await;

    html! {
        script {
            (PreEscaped(r#"
            function copyToClipboard(input) {
                input.select();
                document.execCommand('copy');
                const hint = input.nextElementSibling;
                hint.textContent = 'Copied!';
                setTimeout(() => hint.textContent = 'Click to copy', 2000);
            }
            "#))
        }

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
                            id="wallet-tab"
                            data-bs-toggle="tab"
                            data-bs-target="#wallet-tab-pane"
                            type="button"
                            role="tab"
                        { "Wallet" }
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
                    li class="nav-item" role="presentation" {
                        button class="nav-link"
                            id="payments-tab"
                            data-bs-toggle="tab"
                            data-bs-target="#payments-tab-pane"
                            type="button"
                            role="tab"
                        { "Payments" }
                    }
                    li class="nav-item" role="presentation" {
                        button class="nav-link"
                            id="transactions-tab"
                            data-bs-toggle="tab"
                            data-bs-target="#transactions-tab-pane"
                            type="button"
                            role="tab"
                        { "Transactions" }
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
                                    "Node Type: " strong { "External LND" }
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
                                        tr {
                                            th { "Network" }
                                            td { (network) }
                                        }
                                        tr {
                                            th { "Block Height" }
                                            td { (block_height) }
                                        }
                                        tr {
                                            th { "Status" }
                                            td { (status_badge) }
                                        }
                                        @if let Some(a) = alias {
                                            tr {
                                                th { "Lightning Alias" }
                                                td { (a) }
                                            }
                                        }
                                        @if let Some(pk) = pubkey {
                                            tr {
                                                th { "Lightning Public Key" }
                                                td { (pk) }
                                            }
                                        }
                                    }
                                }
                            }
                            LightningMode::Ldk { lightning_port, .. } => {
                                div id="node-type" class="alert alert-info" {
                                    "Node Type: " strong { "Internal LDK" }
                                }
                                table class="table table-sm mb-0" {
                                    tbody {
                                        tr {
                                            th { "Port" }
                                            td { (lightning_port) }
                                        }
                                        tr {
                                            th { "Network" }
                                            td { (network) }
                                        }
                                        tr {
                                            th { "Block Height" }
                                            td { (block_height) }
                                        }
                                        tr {
                                            th { "Status" }
                                            td { (status_badge) }
                                        }
                                        @if let Some(a) = alias {
                                            tr {
                                                th { "Alias" }
                                                td { (a) }
                                            }
                                        }
                                        @if let Some(pk) = pubkey {
                                            tr {
                                                th { "Public Key" }
                                                td { (pk) }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ──────────────────────────────────────────
                    //   TAB: WALLET
                    // ──────────────────────────────────────────
                    div class="tab-pane fade"
                        id="wallet-tab-pane"
                        role="tabpanel"
                        aria-labelledby="wallet-tab" {

                        div class="d-flex justify-content-between align-items-center mb-2" {
                            div { strong { "Wallet" } }
                            button class="btn btn-sm btn-outline-secondary"
                                hx-get=(WALLET_FRAGMENT_ROUTE)
                                hx-target="#wallet-container"
                                hx-swap="outerHTML"
                                type="button"
                            { "Refresh" }
                        }

                        (wallet_fragment_markup(&balances_result, None, None))
                    }

                    // ──────────────────────────────────────────
                    //   TAB: CHANNELS
                    // ──────────────────────────────────────────
                    div class="tab-pane fade"
                        id="channels-tab-pane"
                        role="tabpanel"
                        aria-labelledby="channels-tab" {

                        div class="d-flex justify-content-between align-items-center mb-2" {
                            div { strong { "Channels" } }
                            button class="btn btn-sm btn-outline-secondary"
                                hx-get=(CHANNEL_FRAGMENT_ROUTE)
                                hx-target="#channels-container"
                                hx-swap="outerHTML"
                                type="button"
                            { "Refresh" }
                        }

                        (channels_fragment_markup(channels_result, None, None, is_lnd))
                    }

                    // ──────────────────────────────────────────
                    //   TAB: PAYMENTS
                    // ──────────────────────────────────────────
                    div class="tab-pane fade"
                        id="payments-tab-pane"
                        role="tabpanel"
                        aria-labelledby="payments-tab" {

                        div class="d-flex justify-content-between align-items-center mb-2" {
                            div { strong { "Payments" } }
                            button class="btn btn-sm btn-outline-secondary"
                                hx-get=(PAYMENTS_FRAGMENT_ROUTE)
                                hx-target="#payments-container"
                                hx-swap="outerHTML"
                                type="button"
                            { "Refresh" }
                        }

                        (payments_fragment_markup(&balances_result, None, None, None))
                    }

                    // ──────────────────────────────────────────
                    //   TAB: TRANSACTIONS
                    // ──────────────────────────────────────────
                    div class="tab-pane fade"
                        id="transactions-tab-pane"
                        role="tabpanel"
                        aria-labelledby="transactions-tab" {

                        (transactions_fragment_markup(&transactions_result, start_secs, end_secs))
                    }
                }
            }
        }
    }
}

pub fn transactions_fragment_markup<E>(
    transactions_result: &Result<ListTransactionsResponse, E>,
    start_secs: u64,
    end_secs: u64,
) -> Markup
where
    E: std::fmt::Display,
{
    // Convert timestamps to datetime-local formatted strings
    let start_dt = match Utc.timestamp_opt(start_secs as i64, 0) {
        LocalResult::Single(dt) => dt.format("%Y-%m-%dT%H:%M:%S").to_string(),
        _ => "1970-01-01T00:00:00".to_string(),
    };

    let end_dt = match Utc.timestamp_opt(end_secs as i64, 0) {
        LocalResult::Single(dt) => dt.format("%Y-%m-%dT%H:%M:%S").to_string(),
        _ => "1970-01-01T00:00:00".to_string(),
    };

    html!(
        div id="transactions-container" {

            // ────────────────────────────────
            //   Date Range Form
            // ────────────────────────────────
            form class="row g-3 mb-3"
                hx-get=(TRANSACTIONS_FRAGMENT_ROUTE)
                hx-target="#transactions-container"
                hx-swap="outerHTML"
            {
                // Start
                div class="col-auto" {
                    label class="form-label" for="start-secs" { "Start" }
                    input
                        class="form-control"
                        type="datetime-local"
                        id="start-secs"
                        name="start_secs"
                        step="1"
                        value=(start_dt);
                }

                // End
                div class="col-auto" {
                    label class="form-label" for="end-secs" { "End" }
                    input
                        class="form-control"
                        type="datetime-local"
                        id="end-secs"
                        name="end_secs"
                        step="1"
                        value=(end_dt);
                }

                // Refresh Button
                div class="col-auto align-self-end" {
                    button class="btn btn-outline-secondary" type="submit" { "Refresh" }
                    button class="btn btn-outline-secondary me-2" type="button"
                        id="last-day-btn"
                    { "Last Day" }
                }
            }

            script {
                (PreEscaped(r#"
                document.getElementById('last-day-btn').addEventListener('click', () => {
                    const now = new Date();
                    const endInput = document.getElementById('end-secs');
                    const startInput = document.getElementById('start-secs');

                    const pad = n => n.toString().padStart(2, '0');

                    const formatUTC = d =>
                        `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;

                    endInput.value = formatUTC(now);

                    const start = new Date(now.getTime() - 24*60*60*1000); // 24 hours ago UTC
                    startInput.value = formatUTC(start);
                });
                "#))
            }

            // ────────────────────────────────
            //   Transaction List
            // ────────────────────────────────
            @match transactions_result {
                Err(err) => {
                    div class="alert alert-danger" {
                        "Failed to load lightning transactions: " (err)
                    }
                }
                Ok(transactions) => {
                    @if transactions.transactions.is_empty() {
                        div class="alert alert-info mt-3" {
                            "No transactions found in this time range."
                        }
                    } @else {
                        ul class="list-group mt-3" {
                            @for tx in &transactions.transactions {
                                li class="list-group-item p-2 mb-1 transaction-item"
                                    style="border-radius: 0.5rem; transition: background-color 0.2s;"
                                {
                                    // Hover effect using inline style (or add a CSS class)
                                    div style="display: flex; justify-content: space-between; align-items: center;" {
                                        // Left: kind + direction + status
                                        div {
                                            div style="font-weight: bold; font-size: 0.9rem;" {
                                                (format!("{:?}", tx.payment_kind))
                                                " — "
                                                span { (format!("{:?}", tx.direction)) }
                                            }

                                            div style="font-size: 0.75rem; margin-top: 2px;" {
                                                @let status_badge = match tx.status {
                                                    PaymentStatus::Pending => html! { span class="badge bg-warning" { "⏳ Pending" } },
                                                    PaymentStatus::Succeeded => html! { span class="badge bg-success" { "✅ Succeeded" } },
                                                    PaymentStatus::Failed => html! { span class="badge bg-danger" { "❌ Failed" } },
                                                };
                                                (status_badge)
                                            }
                                        }

                                        // Right: amount + timestamp
                                        div style="text-align: right;" {
                                            div style="font-weight: bold; font-size: 0.9rem;" {
                                                (format!("{} sats", tx.amount.msats / 1000))
                                            }
                                            div style="font-size: 0.7rem; color: #6c757d;" {
                                                @let timestamp = match Utc.timestamp_opt(tx.timestamp_secs as i64, 0) {
                                                    LocalResult::Single(dt) => dt,
                                                    _ => Utc.timestamp_opt(0, 0).unwrap(),
                                                };
                                                (timestamp.format("%Y-%m-%d %H:%M:%S").to_string())
                                            }
                                        }
                                    }

                                    // Optional hash/preimage, bottom row
                                    @if let Some(hash) = &tx.payment_hash {
                                        div style="font-family: monospace; font-size: 0.7rem; color: #6c757d; margin-top: 2px;" {
                                            "Hash: " (hash.to_string())
                                        }
                                    }

                                    @if let Some(preimage) = &tx.preimage {
                                        div style="font-family: monospace; font-size: 0.7rem; color: #6c757d; margin-top: 1px;" {
                                            "Preimage: " (preimage)
                                        }
                                    }

                                    // Hover effect using inline JS (or move to CSS)
                                    script {
                                        (PreEscaped(r#"
                                        const li = document.currentScript.parentElement;
                                        li.addEventListener('mouseenter', () => li.style.backgroundColor = '#f8f9fa');
                                        li.addEventListener('mouseleave', () => li.style.backgroundColor = 'white');
                                        "#))
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

pub fn payments_fragment_markup<E>(
    balances_result: &Result<GatewayBalances, E>,
    created_invoice: Option<String>,
    success_msg: Option<String>,
    error_msg: Option<String>,
) -> Markup
where
    E: std::fmt::Display,
{
    html!(
        div id="payments-container" {
            @match balances_result {
                Err(err) => {
                    // Error banner — no buttons below
                    div class="alert alert-danger" {
                        "Failed to load lightning balance: " (err)
                    }
                }
                Ok(bal) => {

                    @if let Some(success) = success_msg {
                        div class="alert alert-success mt-2 d-flex justify-content-between align-items-center" {
                            span { (success) }
                        }
                    }

                    @if let Some(error) = error_msg {
                        div class="alert alert-danger mt-2 d-flex justify-content-between align-items-center" {
                            span { (error) }
                        }
                    }

                    div id="lightning-balance-banner"
                        class="alert alert-info d-flex justify-content-between align-items-center" {

                        @let lightning_balance = format!("{}", fedimint_core::Amount::from_msats(bal.lightning_balance_msats));

                        span {
                            "Lightning Balance: "
                            strong id="lightning-balance" { (lightning_balance) }
                        }
                    }

                    // Buttons
                    div class="mt-3" {
                        button class="btn btn-sm btn-outline-primary me-2"
                            type="button"
                            onclick="
                                document.getElementById('receive-form').classList.add('d-none');
                                document.getElementById('pay-invoice-form').classList.toggle('d-none');
                            "
                        { "Send" }

                        button class="btn btn-sm btn-outline-success"
                            type="button"
                            onclick="
                                document.getElementById('pay-invoice-form').classList.add('d-none');
                                document.getElementById('receive-form').classList.toggle('d-none');
                            "
                        { "Receive" }
                    }

                    // Send form
                    div id="pay-invoice-form" class="card card-body mt-3 d-none" {
                        form
                            id="pay-ln-invoice-form"
                            hx-post=(PAY_BOLT11_INVOICE_ROUTE)
                            hx-target="#payments-container"
                            hw-swap="outerHTML"
                        {
                            div class="mb-3" {
                                label class="form-label" for="invoice" { "Bolt11 Invoice" }
                                input type="text"
                                    class="form-control"
                                    id="invoice"
                                    name="invoice"
                                    required;
                            }

                            button
                                type="submit"
                                class="btn btn-success btn-sm"
                            { "Pay Invoice" }
                        }
                    }

                    // Receive form
                    div id="receive-form" class={
                        @if created_invoice.is_some() { "card card-body mt-3 d-none" }
                        @else { "card card-body mt-3 d-none" }
                    } {
                        form
                            id="create-ln-invoice-form"
                            hx-post=(CREATE_BOLT11_INVOICE_ROUTE)
                            hx-target="#payments-container"
                            hx-swap="outerHTML"
                        {
                            div class="mb-3" {
                                label class="form-label" for="amount_msats" { "Amount (msats)" }
                                input type="number"
                                    class="form-control"
                                    id="amount_msats"
                                    name="amount_msats"
                                    min="1"
                                    required;
                            }

                            button
                                type="submit"
                                class="btn btn-success btn-sm"
                            { "Create Bolt11 Invoice" }
                        }
                    }

                    // ──────────────────────────────────────────
                    //  SHOW CREATED INVOICE
                    // ──────────────────────────────────────────
                    @if let Some(invoice) = created_invoice {

                        @let code =
                            QrCode::new(&invoice).expect("Failed to generate QR code");
                        @let qr_svg = code.render::<svg::Color>().build();

                        div class="card card-body mt-4" {

                            div class="card card-body bg-light d-flex flex-column align-items-center" {
                                span class="fw-bold mb-3" { "Bolt11 Invoice:" }

                                // Flex container: address on left, QR on right
                                div class="d-flex flex-row align-items-center gap-3 flex-wrap" style="width: 100%;" {

                                    // Copyable input + text
                                    div class="d-flex flex-column flex-grow-1" style="min-width: 300px;" {
                                        input type="text"
                                            readonly
                                            class="form-control mb-2"
                                            style="text-align:left; font-family: monospace; font-size:1rem;"
                                            value=(invoice)
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
                }
            }
        }
    )
}

pub fn wallet_fragment_markup<E>(
    balances_result: &Result<GatewayBalances, E>,
    success_msg: Option<String>,
    error_msg: Option<String>,
) -> Markup
where
    E: std::fmt::Display,
{
    html!(
        div id="wallet-container" {
            @match balances_result {
                Err(err) => {
                    // Error banner — no buttons below
                    div class="alert alert-danger" {
                        "Failed to load wallet balance: " (err)
                    }
                }
                Ok(bal) => {

                    @if let Some(success) = success_msg {
                        div class="alert alert-success mt-2 d-flex justify-content-between align-items-center" {
                            span { (success) }
                        }
                    }

                    @if let Some(error) = error_msg {
                        div class="alert alert-danger mt-2 d-flex justify-content-between align-items-center" {
                            span { (error) }
                        }
                    }

                    div id="wallet-balance-banner"
                        class="alert alert-info d-flex justify-content-between align-items-center" {

                        @let onchain = format!("{}", bitcoin::Amount::from_sat(bal.onchain_balance_sats));

                        span {
                            "Balance: "
                            strong id="wallet-balance" { (onchain) }
                        }
                    }

                    div class="mt-3" {
                        // Toggle Send Form button
                        button class="btn btn-sm btn-outline-primary me-2"
                            type="button"
                            onclick="
                                document.getElementById('send-form').classList.toggle('d-none');
                                document.getElementById('receive-address-container').innerHTML = '';
                            "
                        { "Send" }


                        button class="btn btn-sm btn-outline-success"
                            hx-get=(LN_ONCHAIN_ADDRESS_ROUTE)
                            hx-target="#receive-address-container"
                            hx-swap="outerHTML"
                            type="button"
                            onclick="document.getElementById('send-form').classList.add('d-none');"
                        { "Receive" }
                    }

                    // ──────────────────────────────────────────
                    //   Send Form (hidden until toggled)
                    // ──────────────────────────────────────────
                    div id="send-form" class="card card-body mt-3 d-none" {

                        form
                            id="send-onchain-form"
                            hx-post=(SEND_ONCHAIN_ROUTE)
                            hx-target="#wallet-container"
                            hx-swap="outerHTML"
                        {
                            // Address
                            div class="mb-3" {
                                label class="form-label" for="address" { "Bitcoin Address" }
                                input
                                    type="text"
                                    class="form-control"
                                    id="address"
                                    name="address"
                                    required;
                            }

                            // Amount + ALL button
                            div class="mb-3" {
                                label class="form-label" for="amount" { "Amount (sats)" }
                                div class="input-group" {
                                    input
                                        type="text"
                                        class="form-control"
                                        id="amount"
                                        name="amount"
                                        placeholder="e.g. 10000 or all"
                                        required;

                                    button
                                        class="btn btn-outline-secondary"
                                        type="button"
                                        onclick="document.getElementById('amount').value = 'all';"
                                    { "All" }
                                }
                            }

                            // Fee Rate
                            div class="mb-3" {
                                label class="form-label" for="fee_rate" { "Sats per vbyte" }
                                input
                                    type="number"
                                    class="form-control"
                                    id="fee_rate"
                                    name="fee_rate_sats_per_vbyte"
                                    min="1"
                                    required;
                            }

                            // Confirm Send
                            div class="mt-3" {
                                button
                                    type="submit"
                                    class="btn btn-sm btn-primary"
                                {
                                    "Confirm Send"
                                }
                            }
                        }
                    }

                    div id="receive-address-container" class="mt-3" {}
                }
            }
        }
    )
}

// channels_fragment_markup converts either the channels Vec or an error string
// into a chunk of HTML (the thing HTMX will replace).
pub fn channels_fragment_markup<E>(
    channels_result: Result<Vec<ChannelInfo>, E>,
    success_msg: Option<String>,
    error_msg: Option<String>,
    is_lnd: bool,
) -> Markup
where
    E: std::fmt::Display,
{
    html! {
        // This outer div is what we'll replace with hx-swap="outerHTML"
        div id="channels-container" {
            @match channels_result {
                Err(err_str) => {
                    div class="alert alert-danger" {
                        "Failed to load channels: " (err_str)
                    }
                }
                Ok(channels) => {

                    @if let Some(success) = success_msg {
                        div class="alert alert-success mt-2 d-flex justify-content-between align-items-center" {
                            span { (success) }
                        }
                    }

                    @if let Some(error) = error_msg {
                        div class="alert alert-danger mt-2 d-flex justify-content-between align-items-center" {
                            span { (error) }
                        }
                    }

                    @if channels.is_empty() {
                        div class="alert alert-info" { "No channels found." }
                    } @else {
                        table class="table table-sm align-middle" {
                            thead {
                                tr {
                                    th { "Remote PubKey" }
                                    th { "Funding OutPoint" }
                                    th { "Size (sats)" }
                                    th { "Active" }
                                    th { "Liquidity" }
                                    th { "" }
                                }
                            }
                            tbody {
                                @for ch in channels {
                                    @let row_id = format!("close-form-{}", ch.remote_pubkey);
                                    // precompute safely (no @let inline arithmetic)
                                    @let size = ch.channel_size_sats.max(1);
                                    @let outbound_pct = (ch.outbound_liquidity_sats as f64 / size as f64) * 100.0;
                                    @let inbound_pct  = (ch.inbound_liquidity_sats  as f64 / size as f64) * 100.0;
                                    @let funding_outpoint = if let Some(funding_outpoint) = ch.funding_outpoint {
                                        funding_outpoint.to_string()
                                    } else {
                                        "".to_string()
                                    };

                                    tr {
                                        td { (ch.remote_pubkey.to_string()) }
                                        td { (funding_outpoint) }
                                        td { (ch.channel_size_sats) }
                                        td {
                                            @if ch.is_active {
                                                span class="badge bg-success" { "active" }
                                            } @else {
                                                span class="badge bg-secondary" { "inactive" }
                                            }
                                        }

                                        // Liquidity bar: single horizontal bar split by two divs
                                        td {
                                            div style="width:240px;" {
                                                div style="display:flex;height:10px;width:100%;border-radius:3px;overflow:hidden" {
                                                    div style=(format!("background:#28a745;width:{:.2}%;", outbound_pct)) {}
                                                    div style=(format!("background:#0d6efd;width:{:.2}%;", inbound_pct)) {}
                                                }

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

                                        td style="width: 70px" {
                                            // X button toggles a per-row collapse
                                            button class="btn btn-sm btn-outline-danger"
                                                type="button"
                                                data-bs-toggle="collapse"
                                                data-bs-target=(format!("#{row_id}"))
                                                aria-expanded="false"
                                                aria-controls=(row_id)
                                            { "X" }
                                        }
                                    }

                                    tr class="collapse" id=(row_id) {
                                        td colspan="6" {
                                            div class="card card-body" {
                                                form
                                                    hx-post=(CLOSE_CHANNEL_ROUTE)
                                                    hx-target="#channels-container"
                                                    hx-swap="outerHTML"
                                                    hx-indicator=(format!("#close-spinner-{}", ch.remote_pubkey))
                                                    hx-disabled-elt="button[type='submit']"
                                                {
                                                    // always required
                                                    input type="hidden"
                                                        name="pubkey"
                                                        value=(ch.remote_pubkey.to_string()) {}

                                                    div class="form-check mb-3" {
                                                        input class="form-check-input"
                                                            type="checkbox"
                                                            name="force"
                                                            value="true"
                                                            id=(format!("force-{}", ch.remote_pubkey))
                                                            onchange=(format!(
                                                                "const input = document.getElementById('sats-vb-{}'); \
                                                                input.disabled = this.checked;",
                                                                ch.remote_pubkey
                                                            )) {}
                                                        label class="form-check-label"
                                                            for=(format!("force-{}", ch.remote_pubkey)) {
                                                            "Force Close"
                                                        }
                                                    }

                                                    // -------------------------------------------
                                                    // CONDITIONAL sats/vbyte input
                                                    // -------------------------------------------
                                                    @if is_lnd {
                                                        div class="mb-3" id=(format!("sats-vb-div-{}", ch.remote_pubkey)) {
                                                            label class="form-label" for=(format!("sats-vb-{}", ch.remote_pubkey)) {
                                                                "Sats per vbyte"
                                                            }
                                                            input
                                                                type="number"
                                                                min="1"
                                                                step="1"
                                                                class="form-control"
                                                                id=(format!("sats-vb-{}", ch.remote_pubkey))
                                                                name="sats_per_vbyte"
                                                                required
                                                                placeholder="Enter fee rate" {}

                                                            small class="text-muted" {
                                                                "Required for LND fee estimation"
                                                            }
                                                        }
                                                    } @else {
                                                        // LDK → auto-filled, hidden
                                                        input type="hidden"
                                                            name="sats_per_vbyte"
                                                            value="1" {}
                                                    }

                                                    // spinner for this specific channel
                                                    div class="htmx-indicator mt-2"
                                                        id=(format!("close-spinner-{}", ch.remote_pubkey)) {
                                                        div class="spinner-border spinner-border-sm text-danger" role="status" {}
                                                        span { " Closing..." }
                                                    }

                                                    button type="submit"
                                                        class="btn btn-danger btn-sm" {
                                                        "Confirm Close"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div class="mt-3" {
                        // Toggle button
                        button id="open-channel-btn" class="btn btn-sm btn-primary"
                            type="button"
                            data-bs-toggle="collapse"
                            data-bs-target="#open-channel-form"
                            aria-expanded="false"
                            aria-controls="open-channel-form"
                        { "Open Channel" }

                        // Collapsible form
                        div id="open-channel-form" class="collapse mt-3" {
                            form hx-post=(OPEN_CHANNEL_ROUTE)
                                hx-target="#channels-container"
                                hx-swap="outerHTML"
                                class="card card-body" {

                                h5 class="card-title" { "Open New Channel" }

                                div class="mb-2" {
                                    label class="form-label" { "Remote Node Public Key" }
                                    input type="text" name="pubkey" class="form-control" placeholder="03abcd..." required {}
                                }

                                div class="mb-2" {
                                    label class="form-label" { "Host" }
                                    input type="text" name="host" class="form-control" placeholder="1.2.3.4:9735" required {}
                                }

                                div class="mb-2" {
                                    label class="form-label" { "Channel Size (sats)" }
                                    input type="number" name="channel_size_sats" class="form-control" placeholder="1000000" required {}
                                }

                                input type="hidden" name="push_amount_sats" value="0" {}

                                button type="submit" class="btn btn-success" { "Confirm Open" }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub async fn channels_fragment_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
) -> Html<String>
where
    E: std::fmt::Display,
{
    let is_lnd = matches!(state.api.lightning_mode(), LightningMode::Lnd { .. });
    let channels_result: Result<_, E> = state.api.handle_list_channels_msg().await;

    let markup = channels_fragment_markup(channels_result, None, None, is_lnd);
    Html(markup.into_string())
}

pub async fn open_channel_handler<E: Display + Send + Sync>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<OpenChannelRequest>,
) -> Html<String> {
    let is_lnd = matches!(state.api.lightning_mode(), LightningMode::Lnd { .. });
    match state.api.handle_open_channel_msg(payload).await {
        Ok(txid) => {
            let channels_result = state.api.handle_list_channels_msg().await;
            let markup = channels_fragment_markup(
                channels_result,
                Some(format!("Successfully initiated channel open. TxId: {txid}")),
                None,
                is_lnd,
            );
            Html(markup.into_string())
        }
        Err(err) => {
            let channels_result = state.api.handle_list_channels_msg().await;
            let markup =
                channels_fragment_markup(channels_result, None, Some(err.to_string()), is_lnd);
            Html(markup.into_string())
        }
    }
}

pub async fn close_channel_handler<E: Display + Send + Sync>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<CloseChannelsWithPeerRequest>,
) -> Html<String> {
    let is_lnd = matches!(state.api.lightning_mode(), LightningMode::Lnd { .. });
    match state.api.handle_close_channels_with_peer_msg(payload).await {
        Ok(_) => {
            let channels_result = state.api.handle_list_channels_msg().await;
            let markup = channels_fragment_markup(
                channels_result,
                Some("Successfully initiated channel close".to_string()),
                None,
                is_lnd,
            );
            Html(markup.into_string())
        }
        Err(err) => {
            let channels_result = state.api.handle_list_channels_msg().await;
            let markup =
                channels_fragment_markup(channels_result, None, Some(err.to_string()), is_lnd);
            Html(markup.into_string())
        }
    }
}

pub async fn send_onchain_handler<E: Display + Send + Sync>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<SendOnchainRequest>,
) -> Html<String> {
    let result = state.api.handle_send_onchain_msg(payload).await;

    let balances = state.api.handle_get_balances_msg().await;

    let markup = match result {
        Ok(txid) => wallet_fragment_markup(
            &balances,
            Some(format!("Send transaction. TxId: {txid}")),
            None,
        ),
        Err(err) => wallet_fragment_markup(&balances, None, Some(err.to_string())),
    };

    Html(markup.into_string())
}

pub async fn wallet_fragment_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
) -> Html<String>
where
    E: std::fmt::Display,
{
    let balances_result = state.api.handle_get_balances_msg().await;
    let markup = wallet_fragment_markup(&balances_result, None, None);
    Html(markup.into_string())
}

pub async fn generate_receive_address_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
) -> Html<String>
where
    E: std::fmt::Display,
{
    let address_result = state.api.handle_get_ln_onchain_address_msg().await;

    let markup = match address_result {
        Ok(address) => {
            // Generate QR code SVG
            let code =
                QrCode::new(address.to_qr_uri().as_bytes()).expect("Failed to generate QR code");
            let qr_svg = code.render::<svg::Color>().build();

            html! {
                div class="card card-body bg-light d-flex flex-column align-items-center" {
                    span class="fw-bold mb-3" { "Deposit Address:" }

                    // Flex container: address on left, QR on right
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
                div class="alert alert-danger" { "Failed to generate address: " (err) }
            }
        }
    };

    Html(markup.into_string())
}

pub async fn payments_fragment_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
) -> Html<String>
where
    E: std::fmt::Display,
{
    let balances_result = state.api.handle_get_balances_msg().await;
    let markup = payments_fragment_markup(&balances_result, None, None, None);
    Html(markup.into_string())
}

pub async fn create_bolt11_invoice_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<CreateInvoiceForOperatorPayload>,
) -> Html<String>
where
    E: std::fmt::Display,
{
    let invoice_result = state
        .api
        .handle_create_invoice_for_operator_msg(payload)
        .await;
    let balances_result = state.api.handle_get_balances_msg().await;

    match invoice_result {
        Ok(invoice) => {
            let markup =
                payments_fragment_markup(&balances_result, Some(invoice.to_string()), None, None);
            Html(markup.into_string())
        }
        Err(e) => {
            let markup = payments_fragment_markup(
                &balances_result,
                None,
                None,
                Some(format!("Failed to create invoice: {e}")),
            );
            Html(markup.into_string())
        }
    }
}

pub async fn pay_bolt11_invoice_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Form(payload): Form<PayInvoiceForOperatorPayload>,
) -> Html<String>
where
    E: std::fmt::Display,
{
    let send_result = state.api.handle_pay_invoice_for_operator_msg(payload).await;
    let balances_result = state.api.handle_get_balances_msg().await;

    match send_result {
        Ok(preimage) => {
            let markup = payments_fragment_markup(
                &balances_result,
                None,
                Some(format!("Successfully paid invoice. Preimage: {preimage}")),
                None,
            );
            Html(markup.into_string())
        }
        Err(e) => {
            let markup = payments_fragment_markup(
                &balances_result,
                None,
                None,
                Some(format!("Failed to pay invoice: {e}")),
            );
            Html(markup.into_string())
        }
    }
}

pub async fn transactions_fragment_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Html<String>
where
    E: std::fmt::Display + std::fmt::Debug,
{
    let now = fedimint_core::time::now();
    let end_secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let start_secs = now
        .checked_sub(std::time::Duration::from_secs(60 * 60 * 24))
        .unwrap_or(now)
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let parse = |key: &str| -> Option<u64> {
        params.get(key).and_then(|s| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                .ok()
                .map(|dt| {
                    let dt_utc: chrono::DateTime<Utc> = Utc.from_utc_datetime(&dt);
                    dt_utc.timestamp() as u64
                })
        })
    };

    let start_secs = parse("start_secs").unwrap_or(start_secs);
    let end_secs = parse("end_secs").unwrap_or(end_secs);

    let transactions_result = state
        .api
        .handle_list_transactions_msg(ListTransactionsPayload {
            start_secs,
            end_secs,
        })
        .await;

    Html(transactions_fragment_markup(&transactions_result, start_secs, end_secs).into_string())
}
