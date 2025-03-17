use fedimint_core::module::audit::AuditSummary;
use maud::{Markup, html};

pub fn render_audit_summary(audit_summary: &AuditSummary) -> Markup {
    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Audit Summary" }
            div class="card-body" {
                // Overall Summary
                div class="mb-3" {
                    div class="alert alert-info" {
                        "Net Assets: " strong { (format!("{} msat", audit_summary.net_assets)) }
                    }
                }

                // Per Module Breakdown
                div class="accordion" id="auditAccordion" {
                    @for (i, (module_id, module_summary)) in audit_summary.module_summaries.iter().enumerate() {
                        div class="accordion-item" {
                            h2 class="accordion-header" id=(format!("heading{}", i)) {
                                button class="accordion-button collapsed" type="button"
                                    data-bs-toggle="collapse" data-bs-target=(format!("#collapse{}", i))
                                    aria-expanded="false" aria-controls=(format!("collapse{}", i)) {
                                    strong { (module_summary.kind) }
                                }
                            }
                            div id=(format!("collapse{}", i)) class="accordion-collapse collapse"
                                aria-labelledby=(format!("heading{}", i)) data-bs-parent="#auditAccordion" {
                                div class="accordion-body" {
                                    table class="table table-sm" {
                                        tr {
                                            th { "Module ID" }
                                            td { (module_id) }
                                        }
                                        tr {
                                            th { "Net Assets" }
                                            td { (format!("{} msat", module_summary.net_assets)) }
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
