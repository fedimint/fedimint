use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::response::Html;
use fedimint_core::config::FederationId;
use fedimint_core::module::serde_json;
use fedimint_core::time::now;
use fedimint_gateway_common::{
    FederationInfo, PaymentLogPayload, PaymentLogResponse, PaymentStats, PaymentSummaryPayload,
    PaymentSummaryResponse,
};
use fedimint_ui_common::UiState;
use fedimint_ui_common::auth::UserAuth;
use maud::{Markup, html};

use crate::{DynGatewayApi, PAYMENT_LOG_ROUTE};

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
                ul class="nav nav-tabs card-header-tabs" role="tablist" {
                    li class="nav-item" {
                        button
                            class="nav-link active"
                            data-bs-toggle="tab"
                            data-bs-target="#payment-summary"
                            type="button"
                        {
                            "Summary"
                        }
                    }
                    li class="nav-item" {
                        button
                            class="nav-link"
                            data-bs-toggle="tab"
                            data-bs-target="#payment-log"
                            type="button"
                        {
                            "Payment Log"
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
            form class="mb-3 d-flex gap-2 align-items-end" {
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
                        hx-include="this"
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
                    hx-include="closest form"
                {
                    "↻ Refresh"
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
        }
    }
}

pub async fn payment_log_fragment_handler<E>(
    State(state): State<UiState<DynGatewayApi<E>>>,
    _auth: UserAuth,
    Query(params): Query<HashMap<String, String>>,
) -> Html<String>
where
    E: std::fmt::Display + std::fmt::Debug,
{
    let federation_id = match params.get("federation_id") {
        Some(v) => match v.parse::<FederationId>() {
            Ok(id) => id,
            Err(_) => {
                return Html(
                    html! {
                        div class="alert alert-danger mb-0" {
                            "Invalid federation ID."
                        }
                    }
                    .into_string(),
                );
            }
        },
        None => {
            return Html(
                html! {
                    div class="alert alert-warning mb-0" {
                        "No federation selected."
                    }
                }
                .into_string(),
            );
        }
    };

    let result = state
        .api
        .handle_payment_log_msg(PaymentLogPayload {
            end_position: None,
            pagination_size: 10,
            federation_id,
            event_kinds: vec![],
        })
        .await;

    Html(render_payment_log_result(&result).into_string())
}

fn render_payment_log_result<E>(result: &Result<PaymentLogResponse, E>) -> Markup
where
    E: std::fmt::Display,
{
    match result {
        Ok(PaymentLogResponse(entries)) if !entries.is_empty() => html! {
            table class="table table-sm table-hover mb-0" {
                thead {
                    tr {
                        th { "Event Kind" }
                        th { "Timestamp" }
                    }
                }
                tbody {
                    @for (idx, entry) in entries.iter().enumerate() {
                        tr {
                            td {
                                code {
                                    (entry.as_raw().kind)
                                }
                            }
                            td {
                                (format_timestamp(entry.as_raw().ts_usecs))
                            }
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

                        // Expandable details row
                        tr
                            id=(format!("payment-details-{}", idx))
                            class="d-none"
                        {
                            td colspan="3" {
                                pre class="bg-dark text-light p-3 rounded small mb-0" {
                                    (serde_json::to_string_pretty(entry)
                                        .unwrap_or_else(|_| "<invalid json>".to_string()))
                                }
                            }
                        }
                    }
                }
            }
        },

        Ok(_) => html! {
            div class="text-muted" {
                "No payment events found for this federation."
            }
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
