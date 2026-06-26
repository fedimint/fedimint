use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::serde_json::{self, Value};
use fedimint_server_core::dashboard_ui::{DashboardModuleFeeConsensus, DynDashboardApi};
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{ROOT_ROUTE, UiState};
use maud::{Markup, html};
use serde::Deserialize;

pub const FEES_SIMPLE_ROUTE: &str = "/fees/simple";
pub const FEES_EXPERT_ROUTE: &str = "/fees/expert";

#[derive(Debug, Deserialize)]
pub struct SimplifiedFeeForm {
    percentage_ppm: u64,
}

#[derive(Debug, Deserialize)]
pub struct ExpertFeeForm {
    module_instance_id: ModuleInstanceId,
    fee_consensus_json: String,
}

pub fn render(fees: &[DashboardModuleFeeConsensus]) -> Markup {
    let simplified = SimplifiedFeeValues::from_fees(fees);

    html! {
        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card" {
                    div class="card-header dashboard-header d-flex justify-content-between align-items-center" {
                        span { "Fee Configuration" }
                        span class="badge bg-secondary" { "Dynamic" }
                    }
                    div class="card-body" {
                        div class="row" {
                            div class="col-lg-4 col-xl-3" {
                                (render_simplified_form(&simplified))
                            }
                        }
                        (render_expert_forms(fees))
                    }
                }
            }
        }
    }
}

fn render_simplified_form(values: &SimplifiedFeeValues) -> Markup {
    html! {
        h5 class="mb-3" { "Simplified" }
        form method="post" action=(FEES_SIMPLE_ROUTE) {
            div class="mb-3" {
                label for="percentage_ppm" class="form-label" { "Economic percentage (ppm)" }
                input type="number" min="0" max="210000" class="form-control" id="percentage_ppm"
                    name="percentage_ppm" value=(values.percentage_ppm) required;
            }
            button type="submit" class="btn btn-primary" {
                i class="bi bi-save me-1" {}
                "Save"
            }
        }
    }
}

fn render_expert_forms(fees: &[DashboardModuleFeeConsensus]) -> Markup {
    html! {
        div class="mt-4" {
            button class="btn btn-outline-secondary" type="button" data-bs-toggle="collapse"
                data-bs-target="#fee-expert-mode" aria-expanded="false" aria-controls="fee-expert-mode" {
                i class="bi bi-sliders me-1" {}
                "Expert"
            }
            div class="collapse mt-3" id="fee-expert-mode" {
                div class="accordion" id="fee-expert-accordion" {
                    @for fee in fees {
                        @let item_id = format!("fee-module-{}", fee.module_instance_id);
                        @let current = fee.desired.as_ref().unwrap_or(&fee.current);
                        @let json = serde_json::to_string_pretty(current)
                            .expect("fee consensus JSON must serialize");
                        div class="accordion-item" {
                            h2 class="accordion-header" {
                                button class="accordion-button collapsed" type="button"
                                    data-bs-toggle="collapse" data-bs-target=(format!("#{item_id}")) {
                                    (format!("{} #{}", fee.module_kind, fee.module_instance_id))
                                }
                            }
                            div id=(item_id) class="accordion-collapse collapse" data-bs-parent="#fee-expert-accordion" {
                                div class="accordion-body" {
                                    form method="post" action=(FEES_EXPERT_ROUTE) {
                                        input type="hidden" name="module_instance_id" value=(fee.module_instance_id);
                                        div class="mb-2 text-muted" {
                                            (format!("Active since consensus unix time {}", fee.active_since.0))
                                            @if fee.desired.is_some() {
                                                " - local desired vote pending"
                                            }
                                        }
                                        textarea class="form-control font-monospace" name="fee_consensus_json"
                                            rows="10" spellcheck="false" {
                                            (json)
                                        }
                                        button type="submit" class="btn btn-outline-primary mt-3" {
                                            i class="bi bi-save me-1" {}
                                            "Save JSON"
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

pub async fn post_simple(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<SimplifiedFeeForm>,
) -> Response {
    let fees = match state.api.module_fee_consensus().await {
        Ok(fees) => fees,
        Err(error) => return bad_request(error),
    };

    for fee in fees {
        let mut fee_consensus = fee.desired.unwrap_or(fee.current);
        if !apply_simplified_fee_policy(&mut fee_consensus, fee.module_kind.as_str(), &form) {
            continue;
        }

        if let Err(error) = state
            .api
            .set_module_fee_consensus_json(fee.module_instance_id, fee_consensus)
            .await
        {
            return bad_request(error);
        }
    }

    Redirect::to(ROOT_ROUTE).into_response()
}

pub async fn post_expert(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<ExpertFeeForm>,
) -> Response {
    let fee_consensus = match serde_json::from_str(&form.fee_consensus_json) {
        Ok(fee_consensus) => fee_consensus,
        Err(error) => return bad_request(format!("Invalid fee consensus JSON: {error}")),
    };

    match state
        .api
        .set_module_fee_consensus_json(form.module_instance_id, fee_consensus)
        .await
    {
        Ok(()) => Redirect::to(ROOT_ROUTE).into_response(),
        Err(error) => bad_request(error),
    }
}

fn bad_request(error: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(
            html! {
                div class="container py-4" {
                    div class="alert alert-danger" { (error) }
                    a class="btn btn-primary" href=(ROOT_ROUTE) { "Return to Dashboard" }
                }
            }
            .into_string(),
        ),
    )
        .into_response()
}

fn apply_simplified_fee_policy(
    fee_consensus: &mut Value,
    module_kind: &str,
    form: &SimplifiedFeeForm,
) -> bool {
    match module_kind {
        "mint" | "mintv2" => {
            set_fee_rate_ppm(fee_consensus, "input", 0);
            set_fee_rate_ppm(fee_consensus, "output", form.percentage_ppm);
            true
        }
        "ln" | "lnv2" => {
            set_fee_rate_ppm(fee_consensus, "incoming_contract_input", 0);
            set_fee_rate_ppm(fee_consensus, "outgoing_contract_input", 0);
            set_fee_rate_ppm(fee_consensus, "incoming_contract_output", 0);
            set_fee_rate_ppm(
                fee_consensus,
                "outgoing_contract_output",
                form.percentage_ppm,
            );
            true
        }
        _ => false,
    }
}

fn set_fee_rate_ppm(fee_consensus: &mut Value, field: &str, parts_per_million: u64) {
    let Some(rate) = fee_consensus
        .as_object_mut()
        .and_then(|fields| fields.get_mut(field))
        .and_then(Value::as_object_mut)
    else {
        return;
    };

    rate.insert(
        "parts_per_million".to_owned(),
        Value::from(parts_per_million),
    );
}

#[derive(Debug, Default)]
struct SimplifiedFeeValues {
    percentage_ppm: u64,
}

impl SimplifiedFeeValues {
    fn from_fees(fees: &[DashboardModuleFeeConsensus]) -> Self {
        let mut values = Self::default();

        for fee in fees {
            let fee_consensus = fee.desired.as_ref().unwrap_or(&fee.current);
            match fee.module_kind.as_str() {
                "mint" | "mintv2" => {
                    if let Some(ppm) = get_fee_rate_ppm(fee_consensus, "output") {
                        values.percentage_ppm = values.percentage_ppm.max(ppm);
                    }
                }
                "ln" | "lnv2" => {
                    if let Some(ppm) = get_fee_rate_ppm(fee_consensus, "outgoing_contract_output") {
                        values.percentage_ppm = values.percentage_ppm.max(ppm);
                    }
                }
                _ => {}
            }
        }

        values
    }
}

#[cfg(test)]
fn get_fee_rate_base(fee_consensus: &Value, field: &str) -> Option<u64> {
    fee_consensus
        .get(field)
        .and_then(|rate| rate.get("base"))
        .and_then(Value::as_u64)
}

fn get_fee_rate_ppm(fee_consensus: &Value, field: &str) -> Option<u64> {
    fee_consensus
        .get(field)
        .and_then(|rate| rate.get("parts_per_million"))
        .and_then(Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simplified_policy_preserves_expert_only_fields() {
        let form = SimplifiedFeeForm { percentage_ppm: 14 };

        let mut mint = serde_json::json!({
            "input": { "base": 1, "parts_per_million": 2 },
            "output": { "base": 3, "parts_per_million": 4 }
        });
        assert!(apply_simplified_fee_policy(&mut mint, "mint", &form));
        assert_eq!(get_fee_rate_base(&mint, "input"), Some(1));
        assert_eq!(get_fee_rate_ppm(&mint, "input"), Some(0));
        assert_eq!(get_fee_rate_base(&mint, "output"), Some(3));
        assert_eq!(get_fee_rate_ppm(&mint, "output"), Some(form.percentage_ppm));

        let mut ln = serde_json::json!({
            "incoming_contract_input": { "base": 1, "parts_per_million": 2 },
            "incoming_contract_output": { "base": 3, "parts_per_million": 4 },
            "outgoing_contract_input": { "base": 5, "parts_per_million": 6 },
            "outgoing_contract_output": { "base": 7, "parts_per_million": 8 },
            "offer": 9
        });
        assert!(apply_simplified_fee_policy(&mut ln, "ln", &form));
        assert_eq!(get_fee_rate_base(&ln, "incoming_contract_input"), Some(1));
        assert_eq!(get_fee_rate_ppm(&ln, "incoming_contract_input"), Some(0));
        assert_eq!(get_fee_rate_base(&ln, "incoming_contract_output"), Some(3));
        assert_eq!(get_fee_rate_ppm(&ln, "incoming_contract_output"), Some(0));
        assert_eq!(get_fee_rate_base(&ln, "outgoing_contract_input"), Some(5));
        assert_eq!(get_fee_rate_ppm(&ln, "outgoing_contract_input"), Some(0));
        assert_eq!(get_fee_rate_base(&ln, "outgoing_contract_output"), Some(7));
        assert_eq!(
            get_fee_rate_ppm(&ln, "outgoing_contract_output"),
            Some(form.percentage_ppm)
        );
        assert_eq!(ln.get("offer").and_then(Value::as_u64), Some(9));

        let mut wallet = serde_json::json!({
            "peg_in": { "base": 1, "parts_per_million": 2 },
            "peg_out": { "base": 3, "parts_per_million": 4 }
        });
        assert!(!apply_simplified_fee_policy(&mut wallet, "wallet", &form));
        assert_eq!(get_fee_rate_base(&wallet, "peg_in"), Some(1));
        assert_eq!(get_fee_rate_ppm(&wallet, "peg_in"), Some(2));
        assert_eq!(get_fee_rate_base(&wallet, "peg_out"), Some(3));
        assert_eq!(get_fee_rate_ppm(&wallet, "peg_out"), Some(4));

        let mut unsupported = serde_json::json!(null);
        assert!(!apply_simplified_fee_policy(
            &mut unsupported,
            "meta",
            &form
        ));
    }
}
