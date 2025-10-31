use fedimint_core::Amount;
use fedimint_gateway_common::FederationInfo;
use maud::{Markup, html};

pub fn render(fed: &FederationInfo) -> Markup {
    html!(
        @let bal = fed.balance_msat;
        @let balance_class = if bal == Amount::ZERO {
            "alert alert-danger"
        } else {
            "alert alert-success"
        };

        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card h-100" {
                    div class="card-header dashboard-header" {
                        (fed.federation_name.clone().unwrap_or("Unnamed Federation".to_string()))
                    }
                    div class="card-body" {
                        div id="balance" class=(balance_class) {
                            "Balance: " strong { (fed.balance_msat) }
                        }
                        table class="table table-sm mb-0" {
                            tbody {
                                tr {
                                    th { "Federation ID" }
                                    td { (fed.federation_id) }
                                }
                                tr {
                                    th { "Lightning Fee" }
                                    td {
                                        table class="table table-sm mb-0" {
                                            tbody {
                                                tr {
                                                    th { "Base Fee" }
                                                    td { (fed.config.lightning_fee.base) }
                                                }
                                                tr {
                                                    th { "Parts Per Million" }
                                                    td { (fed.config.lightning_fee.parts_per_million) }
                                                }
                                            }
                                        }
                                    }
                                }
                                tr {
                                    th { "Transaction Fee" }
                                    td {
                                        table class="table table-sm mb-0" {
                                            tbody {
                                                tr {
                                                    th { "Base Fee" }
                                                    td { (fed.config.transaction_fee.base) }
                                                }
                                                tr {
                                                    th { "Parts Per Million" }
                                                    td { (fed.config.transaction_fee.parts_per_million) }
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
    )
}
