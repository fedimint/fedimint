use std::fmt::Display;

use axum::Form;
use axum::extract::State;
use axum::response::Html;
use fedimint_core::bitcoin::Network;
use fedimint_gateway_common::{
    ChannelInfo, CloseChannelsWithPeerRequest, GatewayInfo, LightningInfo, LightningMode,
    OpenChannelRequest,
};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{Markup, html};

use crate::{CHANNEL_FRAGMENT_ROUTE, DynGatewayApi};

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

    html! {
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
                            id="channels-tab"
                            data-bs-toggle="tab"
                            data-bs-target="#channels-tab-pane"
                            type="button"
                            role="tab"
                        { "Channels" }
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
                }
            }
        }
    }
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
                                        td colspan="5" {
                                            div class="card card-body" {
                                                form
                                                    hx-post="/ui/channels/close"
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
                            form hx-post="/ui/channels/open"
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
                Some(format!("Successfully initiated channel close")),
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
