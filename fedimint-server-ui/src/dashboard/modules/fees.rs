use std::collections::BTreeMap;

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
    ecash_input_base_msats: u64,
    ecash_output_base_msats: u64,
    peg_in_base_msats: u64,
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
                        div class="row gy-4" {
                            div class="col-lg-4" {
                                (render_simplified_form(&simplified))
                            }
                            div class="col-lg-8" {
                                (render_expert_forms(fees))
                            }
                        }
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
                label for="ecash_input_base_msats" class="form-label" { "Ecash input base (msats)" }
                input type="number" min="0" class="form-control" id="ecash_input_base_msats"
                    name="ecash_input_base_msats" value=(values.ecash_input_base_msats) required;
            }
            div class="mb-3" {
                label for="ecash_output_base_msats" class="form-label" { "Ecash output base (msats)" }
                input type="number" min="0" class="form-control" id="ecash_output_base_msats"
                    name="ecash_output_base_msats" value=(values.ecash_output_base_msats) required;
            }
            div class="mb-3" {
                label for="peg_in_base_msats" class="form-label" { "Peg-in base (msats)" }
                input type="number" min="0" class="form-control" id="peg_in_base_msats"
                    name="peg_in_base_msats" value=(values.peg_in_base_msats) required;
            }
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
        h5 class="mb-3" { "Expert" }
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
            set_fee_rate(
                fee_consensus,
                "input",
                Some(form.ecash_input_base_msats),
                Some(0),
            );
            set_fee_rate(
                fee_consensus,
                "output",
                Some(form.ecash_output_base_msats),
                Some(form.percentage_ppm),
            );
            true
        }
        "wallet" | "walletv2" => {
            set_fee_rate(
                fee_consensus,
                "peg_in",
                Some(form.peg_in_base_msats),
                Some(0),
            );
            true
        }
        "ln" | "lnv2" => {
            set_fee_rate(fee_consensus, "incoming_contract_input", None, Some(0));
            set_fee_rate(fee_consensus, "outgoing_contract_input", None, Some(0));
            set_fee_rate(fee_consensus, "incoming_contract_output", None, Some(0));
            set_fee_rate(
                fee_consensus,
                "outgoing_contract_output",
                None,
                Some(form.percentage_ppm),
            );
            true
        }
        _ => false,
    }
}

fn set_fee_rate(
    fee_consensus: &mut Value,
    field: &str,
    base_msats: Option<u64>,
    parts_per_million: Option<u64>,
) {
    let Some(rate) = fee_consensus
        .as_object_mut()
        .and_then(|fields| fields.get_mut(field))
        .and_then(Value::as_object_mut)
    else {
        return;
    };

    if let Some(base_msats) = base_msats {
        rate.insert("base".to_owned(), Value::from(base_msats));
    }

    if let Some(parts_per_million) = parts_per_million {
        rate.insert(
            "parts_per_million".to_owned(),
            Value::from(parts_per_million),
        );
    }
}

#[derive(Debug, Default)]
struct SimplifiedFeeValues {
    ecash_input_base_msats: u64,
    ecash_output_base_msats: u64,
    peg_in_base_msats: u64,
    percentage_ppm: u64,
}

impl SimplifiedFeeValues {
    fn from_fees(fees: &[DashboardModuleFeeConsensus]) -> Self {
        let mut values = Self::default();
        let mut percentages = BTreeMap::new();

        for fee in fees {
            let fee_consensus = fee.desired.as_ref().unwrap_or(&fee.current);
            match fee.module_kind.as_str() {
                "mint" | "mintv2" => {
                    values.ecash_input_base_msats =
                        get_fee_rate_base(fee_consensus, "input").unwrap_or_default();
                    values.ecash_output_base_msats =
                        get_fee_rate_base(fee_consensus, "output").unwrap_or_default();
                    if let Some(ppm) = get_fee_rate_ppm(fee_consensus, "output") {
                        percentages.insert(fee.module_instance_id, ppm);
                    }
                }
                "wallet" | "walletv2" => {
                    values.peg_in_base_msats =
                        get_fee_rate_base(fee_consensus, "peg_in").unwrap_or_default();
                }
                "ln" | "lnv2" => {
                    if let Some(ppm) = get_fee_rate_ppm(fee_consensus, "outgoing_contract_output") {
                        percentages.insert(fee.module_instance_id, ppm);
                    }
                }
                _ => {}
            }
        }

        values.percentage_ppm = percentages.values().copied().max().unwrap_or_default();
        values
    }
}

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
        let form = SimplifiedFeeForm {
            ecash_input_base_msats: 11,
            ecash_output_base_msats: 12,
            peg_in_base_msats: 13,
            percentage_ppm: 14,
        };

        let mut ln = serde_json::json!({
            "incoming_contract_input": { "base": 1, "parts_per_million": 2 },
            "incoming_contract_output": { "base": 3, "parts_per_million": 4 },
            "outgoing_contract_input": { "base": 5, "parts_per_million": 6 },
            "outgoing_contract_output": { "base": 7, "parts_per_million": 8 },
            "offer": 9
        });
        assert!(apply_simplified_fee_policy(&mut ln, "ln", &form));
        assert_eq!(get_fee_rate_ppm(&ln, "incoming_contract_input"), Some(0));
        assert_eq!(get_fee_rate_ppm(&ln, "incoming_contract_output"), Some(0));
        assert_eq!(get_fee_rate_ppm(&ln, "outgoing_contract_input"), Some(0));
        assert_eq!(
            get_fee_rate_ppm(&ln, "outgoing_contract_output"),
            Some(form.percentage_ppm)
        );
        assert_eq!(ln.get("offer").and_then(Value::as_u64), Some(9));

        let mut wallet = serde_json::json!({
            "peg_in": { "base": 1, "parts_per_million": 2 },
            "peg_out": { "base": 3, "parts_per_million": 4 }
        });
        assert!(apply_simplified_fee_policy(&mut wallet, "wallet", &form));
        assert_eq!(
            get_fee_rate_base(&wallet, "peg_in"),
            Some(form.peg_in_base_msats)
        );
        assert_eq!(get_fee_rate_ppm(&wallet, "peg_in"), Some(0));
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
