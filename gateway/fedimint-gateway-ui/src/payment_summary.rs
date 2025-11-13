use std::time::{Duration, UNIX_EPOCH};

use fedimint_core::time::now;
use fedimint_gateway_common::{PaymentStats, PaymentSummaryPayload, PaymentSummaryResponse};
use maud::{Markup, html};

use crate::DynGatewayApi;

pub async fn render<E>(api: &DynGatewayApi<E>) -> Markup
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

    match payment_summary {
        Ok(summary) => render_summary(&summary),
        Err(e) => html! {
            div class="card h-100 border-danger" {
                div class="card-header dashboard-header bg-danger text-white" {
                    "Payment Summary"
                }
                div class="card-body" {
                    div class="alert alert-danger mb-0" {
                        strong { "Failed to fetch payment summary: " }
                        (e.to_string())
                    }
                }
            }
        },
    }
}

fn render_summary(summary: &PaymentSummaryResponse) -> Markup {
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

fn format_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{} ms", d.as_millis())
    }
}
