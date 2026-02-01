use std::time::{Duration, UNIX_EPOCH};

use axum::extract::{Query, RawQuery, State};
use axum::response::Html;
use fedimint_core::config::FederationId;
use fedimint_core::module::serde_json;
use fedimint_core::time::now;
use fedimint_eventlog::{Event, EventKind, EventLogId};
use fedimint_gateway_common::{
    FederationInfo, PaymentLogPayload, PaymentLogResponse, PaymentStats, PaymentSummaryPayload,
    PaymentSummaryResponse,
};
use fedimint_gwv2_client::events::{
    CompleteLightningPaymentSucceeded, IncomingPaymentFailed, IncomingPaymentStarted,
    IncomingPaymentSucceeded, OutgoingPaymentFailed, OutgoingPaymentStarted,
    OutgoingPaymentSucceeded,
};
use fedimint_mint_client::event::{OOBNotesReissued, OOBNotesSpent};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use fedimint_wallet_client::events::{DepositConfirmed, WithdrawRequest};
use maud::{Markup, PreEscaped, html};
use serde::Deserialize;

use crate::{DynGatewayApi, PAYMENT_LOG_ROUTE};

/// Event categories for UI display - Lightning events
const LIGHTNING_EVENTS: &[(&str, EventKind)] = &[
    ("Outgoing Started", OutgoingPaymentStarted::KIND),
    ("Outgoing Succeeded", OutgoingPaymentSucceeded::KIND),
    ("Outgoing Failed", OutgoingPaymentFailed::KIND),
    ("Incoming Started", IncomingPaymentStarted::KIND),
    ("Incoming Succeeded", IncomingPaymentSucceeded::KIND),
    ("Incoming Failed", IncomingPaymentFailed::KIND),
    (
        "Complete LN Payment",
        CompleteLightningPaymentSucceeded::KIND,
    ),
];

/// Event categories for UI display - Wallet events
const WALLET_EVENTS: &[(&str, EventKind)] = &[
    ("Withdraw Request", WithdrawRequest::KIND),
    ("Deposit Confirmed", DepositConfirmed::KIND),
];

/// Event categories for UI display - E-cash events
const ECASH_EVENTS: &[(&str, EventKind)] = &[
    ("Notes Spent", OOBNotesSpent::KIND),
    ("Notes Reissued", OOBNotesReissued::KIND),
];

/// Query parameters for the payment log handler
/// Note: event_kinds is parsed separately from the raw query string
/// because serde_urlencoded doesn't handle repeated params well
#[derive(Debug, Deserialize)]
pub struct PaymentLogQueryParams {
    pub federation_id: Option<String>,
    pub end_position: Option<EventLogId>,
}

pub async fn render<E>(api: &DynGatewayApi<E>, federations: &[FederationInfo]) -> Markup
where
    E: std::fmt::Display,
{
    let now = now();
    let now_millis = now
        .duration_since(UNIX_EPOCH)
        .expect("Before unix epoch")
        .as_millis() as u64;

    let one_day_ago = now
        .checked_sub(Duration::from_secs(60 * 60 * 24))
        .expect("Before unix epoch");
    let one_day_ago_millis = one_day_ago
        .duration_since(UNIX_EPOCH)
        .expect("Before unix epoch")
        .as_millis() as u64;

    // Fetch payment summary safely
    let payment_summary = api
        .handle_payment_summary_msg(PaymentSummaryPayload {
            start_millis: one_day_ago_millis,
            end_millis: now_millis,
        })
        .await;

    render_tabs(payment_summary, federations)
}

fn render_tabs(
    summary: Result<PaymentSummaryResponse, impl std::fmt::Display>,
    federations: &[FederationInfo],
) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" {
                ul class="nav nav-tabs card-header-tabs w-100" role="tablist" {
                    li class="nav-item flex-fill text-center" {
                        button
                            class="nav-link active w-100"
                            data-bs-toggle="tab"
                            data-bs-target="#payment-summary"
                            type="button"
                        {
                            "Summary"
                        }
                    }
                    li class="nav-item flex-fill text-center" {
                        button
                            class="nav-link w-100"
                            data-bs-toggle="tab"
                            data-bs-target="#payment-log"
                            type="button"
                        {
                            "Payment Events"
                        }
                    }
                }
            }

            div class="card-body tab-content" {
                div
                    class="tab-pane fade show active"
                    id="payment-summary"
                {
                    (render_summary_tab(summary))
                }

                div
                    class="tab-pane fade"
                    id="payment-log"
                {
                    (render_payment_log_tab_initial(federations))
                }
            }
        }
    }
}

fn render_summary_tab(summary: Result<PaymentSummaryResponse, impl std::fmt::Display>) -> Markup {
    match summary {
        Ok(summary) => render_summary_body(&summary),
        Err(e) => html! {
            div class="alert alert-danger mb-0" {
                strong { "Failed to load payment summary: " }
                (e.to_string())
            }
        },
    }
}

fn render_summary_body(summary: &PaymentSummaryResponse) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Payment Summary (Last 24h)" }
            div class="card-body" {
                div class="row" {
                    div class="col-md-6" {
                        (render_stats_table("Outgoing Payments", &summary.outgoing, "text-danger"))
                    }
                    div class="col-md-6" {
                        (render_stats_table("Incoming Payments", &summary.incoming, "text-success"))
                    }
                }
            }
        }
    }
}

fn render_stats_table(title: &str, stats: &PaymentStats, title_class: &str) -> Markup {
    html! {
        div {
            h5 class=(format!("{} mb-3", title_class)) { (title) }

            table class="table table-sm mb-0" {
                tbody {
                    tr {
                        th { "✅ Total Success" }
                        td { (stats.total_success) }
                    }
                    tr {
                        th { "❌ Total Failure" }
                        td { (stats.total_failure) }
                    }
                    tr {
                        th { "💸 Total Fees" }
                        td { (format!("{} msats", stats.total_fees.msats)) }
                    }
                    tr {
                        th { "⚡ Average Latency" }
                        td {
                            (match stats.average_latency {
                                Some(d) => format_duration(d),
                                None => "—".into(),
                            })
                        }
                    }
                    tr {
                        th { "📈 Median Latency" }
                        td {
                            (match stats.median_latency {
                                Some(d) => format_duration(d),
                                None => "—".into(),
                            })
                        }
                    }
                }
            }
        }
    }
}

fn render_payment_log_tab_initial(federations: &[FederationInfo]) -> Markup {
    html! {
        div {
            form id="payment-log-form" class="mb-3" {
                div class="d-flex gap-2 align-items-end mb-2" {
                    div class="flex-grow-1" {
                        label class="form-label fw-bold" {
                            "Federation"
                        }

                        select
                            class="form-select form-select-sm"
                            name="federation_id"
                            hx-get=(PAYMENT_LOG_ROUTE)
                            hx-trigger="change"
                            hx-target="#payment-log-content"
                            hx-include="#payment-log-form"
                        {
                            option value="" selected disabled {
                                "Select a federation…"
                            }

                            @for fed in federations {
                                option value=(fed.federation_id.to_string()) {
                                    (fed.federation_name.clone().unwrap_or_default())
                                }
                            }
                        }
                    }

                    button
                        type="button"
                        class="btn btn-outline-secondary btn-sm"
                        title="Refresh payment log"
                        hx-get=(PAYMENT_LOG_ROUTE)
                        hx-target="#payment-log-content"
                        hx-include="#payment-log-form"
                    {
                        "↻ Refresh"
                    }
                }

                // Collapsible filter section
                div {
                    button
                        type="button"
                        class="btn btn-sm btn-outline-secondary"
                        data-bs-toggle="collapse"
                        data-bs-target="#event-filter-collapse"
                        aria-expanded="false"
                        aria-controls="event-filter-collapse"
                    {
                        "▼ Filter by Event Type"
                    }

                    div class="collapse mt-2" id="event-filter-collapse" {
                        div class="card card-body" {
                            // Lightning Events
                            (render_event_category("Lightning", "lightning", LIGHTNING_EVENTS))

                            // Wallet Events
                            (render_event_category("Wallet", "wallet", WALLET_EVENTS))

                            // E-cash Events
                            (render_event_category("E-cash", "ecash", ECASH_EVENTS))

                            // Apply Filters button
                            div class="mt-3" {
                                button
                                    type="button"
                                    class="btn btn-primary btn-sm"
                                    hx-get=(PAYMENT_LOG_ROUTE)
                                    hx-target="#payment-log-content"
                                    hx-include="#payment-log-form"
                                {
                                    "Apply Filters"
                                }
                            }
                        }
                    }
                }
            }

            div
                id="payment-log-content"
                class="mt-3"
            {
                div class="text-muted" {
                    "Select a federation to view payment events."
                }
            }

            // JavaScript for toggle all/none functionality
            script {
                (PreEscaped(r#"
                function toggleEventGroup(group, checked) {
                    document.querySelectorAll('.' + group + '-event').forEach(function(cb) {
                        cb.checked = checked;
                    });
                }
                "#))
            }
        }
    }
}

/// Renders a category of event checkboxes
fn render_event_category(title: &str, css_class: &str, events: &[(&str, EventKind)]) -> Markup {
    html! {
        div class="mb-3" {
            div class="d-flex align-items-center gap-2 mb-2" {
                strong { (title) }
                button
                    type="button"
                    class="btn btn-outline-secondary btn-sm py-0 px-1"
                    onclick=(format!("toggleEventGroup('{}', true)", css_class))
                {
                    "All"
                }
                button
                    type="button"
                    class="btn btn-outline-secondary btn-sm py-0 px-1"
                    onclick=(format!("toggleEventGroup('{}', false)", css_class))
                {
                    "None"
                }
            }
            div class="row" {
                @for (label, kind) in events {
                    div class="col-6 col-md-4" {
                        div class="form-check" {
                            input
                                type="checkbox"
                                class=(format!("form-check-input {}-event", css_class))
                                name="event_kinds"
                                value=(kind.to_string())
                                checked;
                            label class="form-check-label small" {
                                (label)
                            }
                        }
                    }
                }
            }
        }
    }
}

pub async fn payment_log_fragment_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    RawQuery(raw_query): RawQuery,
    Query(params): Query<PaymentLogQueryParams>,
) -> Html<String>
where
    E: std::fmt::Display + std::fmt::Debug,
{
    let federation_id = match &params.federation_id {
        Some(v) => match v.parse::<FederationId>() {
            Ok(id) => id,
            Err(_) => {
                return Html(
                    html! {
                        div class="alert alert-danger mb-0" { "Invalid federation ID." }
                    }
                    .into_string(),
                );
            }
        },
        None => {
            return Html(
                html! {
                    div class="alert alert-warning mb-0" { "No federation selected." }
                }
                .into_string(),
            );
        }
    };

    let pagination_size = 10;

    // Parse event_kinds from raw query string to handle repeated params
    // serde_urlencoded doesn't properly deserialize repeated params into Vec
    let event_kinds: Vec<EventKind> = parse_event_kinds_from_query(raw_query.as_deref());

    let result = state
        .api
        .handle_payment_log_msg(PaymentLogPayload {
            end_position: params.end_position,
            pagination_size,
            federation_id,
            event_kinds: event_kinds.clone(),
        })
        .await;

    Html(render_payment_log_result(&result, federation_id, &event_kinds).into_string())
}

/// Parse event_kinds from raw query string, handling repeated params
fn parse_event_kinds_from_query(query: Option<&str>) -> Vec<EventKind> {
    let Some(query) = query else {
        return vec![];
    };

    url::form_urlencoded::parse(query.as_bytes())
        .filter_map(|(key, value)| {
            if key == "event_kinds" || key == "event_kinds[]" {
                Some(EventKind::from(value.into_owned()))
            } else {
                None
            }
        })
        .collect()
}

fn render_payment_log_result<E>(
    result: &Result<PaymentLogResponse, E>,
    federation_id: FederationId,
    event_kinds: &[EventKind],
) -> Markup
where
    E: std::fmt::Display,
{
    // Convert event kinds to strings for JSON serialization
    let event_kinds_strings: Vec<String> = event_kinds.iter().map(ToString::to_string).collect();

    match result {
        Ok(PaymentLogResponse(entries)) if !entries.is_empty() => {
            // Compute next end_position as last entry position - 1
            let next_end_position = entries.last().expect("Cannot be empty").id().checked_sub(1);

            html! {
                div {
                    table class="table table-sm table-hover mb-2" {
                        thead {
                            tr {
                                th { "Event Kind" }
                                th { "Timestamp" }
                                th { "Details" }
                            }
                        }
                        tbody {
                            @for (idx, entry) in entries.iter().enumerate() {
                                tr {
                                    td { code { (entry.as_raw().kind) } }
                                    td { (format_timestamp(entry.as_raw().ts_usecs)) }
                                    td {
                                        button
                                            class="btn btn-sm btn-outline-secondary"
                                            type="button"
                                            onclick=(format!(
                                                "document.getElementById('payment-details-{}').classList.toggle('d-none');",
                                                idx
                                            ))
                                        {
                                            "Details"
                                        }
                                    }
                                }

                                tr id=(format!("payment-details-{}", idx)) class="d-none" {
                                    td colspan="3" {
                                        pre class="bg-dark text-light p-3 rounded small mb-0" {
                                            (serde_json::to_string_pretty(entry).unwrap_or_else(|_| "<invalid json>".to_string()))
                                        }
                                    }
                                }
                            }
                        }
                    }

                    @if let Some(next_pos) = next_end_position {
                        div class="d-flex justify-content-end" {
                            button
                                class="btn btn-sm btn-outline-primary"
                                type="button"
                                hx-get=(PAYMENT_LOG_ROUTE)
                                hx-target="#payment-log-content"
                                hx-include="closest form"
                                hx-vals=(serde_json::json!({
                                    "federation_id": federation_id.to_string(),
                                    "end_position": next_pos,
                                    "event_kinds": event_kinds_strings
                                }))
                            {
                                "Next"
                            }
                        }
                    }
                }
            }
        }
        Ok(_) => html! {
            div class="text-muted" { "No payment events found for this federation." }
        },
        Err(e) => html! {
            div class="alert alert-danger mb-0" {
                strong { "Failed to load payment log: " }
                (e.to_string())
            }
        },
    }
}

fn format_timestamp(ts_usecs: u64) -> String {
    let secs = ts_usecs / 1_000_000;
    let nanos = (ts_usecs % 1_000_000) * 1_000;

    let ts = UNIX_EPOCH + Duration::new(secs, nanos as u32);
    let dt: chrono::DateTime<chrono::Utc> = ts.into();

    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn format_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{} ms", d.as_millis())
    }
}
