use maud::{Markup, html};

// Function to render the Wallet module UI section
pub async fn render(wallet: &fedimint_wallet_server::Wallet) -> Markup {
    let consensus_block_count = wallet.consensus_block_count_ui().await;
    let consensus_fee_rate = wallet.consensus_feerate_ui().await;
    let wallet_summary = wallet.get_wallet_summary_ui().await;

    // Calculate total spendable balance
    let total_spendable: u64 = wallet_summary
        .spendable_utxos
        .iter()
        .map(|utxo| utxo.amount.to_sat())
        .sum();

    // Calculate pending outgoing (unsigned + unconfirmed)
    let total_pending_outgoing: u64 = wallet_summary
        .unsigned_peg_out_txos
        .iter()
        .chain(wallet_summary.unconfirmed_peg_out_txos.iter())
        .map(|txo| txo.amount.to_sat())
        .sum();

    // Calculate pending incoming change
    let total_pending_change: u64 = wallet_summary
        .unsigned_change_utxos
        .iter()
        .chain(wallet_summary.unconfirmed_change_utxos.iter())
        .map(|txo| txo.amount.to_sat())
        .sum();

    html! {
        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { "Wallet" }
                    div class="card-body" {
                        // Blockchain status information
                        div class="mb-4" {
                            h5 { "Blockchain Status" }
                            table class="table" {
                                tr {
                                    th { "Consensus Block Count" }
                                    td { (consensus_block_count) }
                                }
                                tr {
                                    th { "Consensus Fee Rate" }
                                    td { (consensus_fee_rate.sats_per_kvb) " sats/kvB" }
                                }
                            }
                        }

                        // Wallet Balance Summary
                        div class="mb-4" {
                            h5 { "Balance Summary" }
                            div class="row" {
                                div class="col-md-4" {
                                    div class="card bg-light mb-3" {
                                        div class="card-body text-center" {
                                            h6 class="card-title" { "Spendable Balance" }
                                            p class="card-text fs-4" { (total_spendable) " sats" }
                                        }
                                    }
                                }
                                div class="col-md-4" {
                                    div class="card bg-light mb-3" {
                                        div class="card-body text-center" {
                                            h6 class="card-title" { "Pending Outgoing" }
                                            p class="card-text fs-4" { (total_pending_outgoing) " sats" }
                                        }
                                    }
                                }
                                div class="col-md-4" {
                                    div class="card bg-light mb-3" {
                                        div class="card-body text-center" {
                                            h6 class="card-title" { "Pending Change" }
                                            p class="card-text fs-4" { (total_pending_change) " sats" }
                                        }
                                    }
                                }
                            }
                        }

                        // UTXOs Breakdown
                        div class="mb-4" {
                            h5 { "UTXO Details" }

                            // Tabs for different UTXO categories
                            ul class="nav nav-tabs" id="walletTabs" role="tablist" {
                                li class="nav-item" role="presentation" {
                                    button class="nav-link active" id="spendable-tab" data-bs-toggle="tab"
                                        data-bs-target="#spendable" type="button" role="tab" aria-controls="spendable"
                                        aria-selected="true" {
                                        "Spendable UTXOs "
                                        span class="badge bg-primary" { (wallet_summary.spendable_utxos.len()) }
                                    }
                                }
                                li class="nav-item" role="presentation" {
                                    button class="nav-link" id="unsigned-tab" data-bs-toggle="tab"
                                        data-bs-target="#unsigned" type="button" role="tab" aria-controls="unsigned"
                                        aria-selected="false" {
                                        "Unsigned Outputs "
                                        span class="badge bg-secondary" {
                                            (wallet_summary.unsigned_peg_out_txos.len() + wallet_summary.unsigned_change_utxos.len())
                                        }
                                    }
                                }
                                li class="nav-item" role="presentation" {
                                    button class="nav-link" id="unconfirmed-tab" data-bs-toggle="tab"
                                        data-bs-target="#unconfirmed" type="button" role="tab" aria-controls="unconfirmed"
                                        aria-selected="false" {
                                        "Unconfirmed Outputs "
                                        span class="badge bg-warning" {
                                            (wallet_summary.unconfirmed_peg_out_txos.len() + wallet_summary.unconfirmed_change_utxos.len())
                                        }
                                    }
                                }
                            }

                            // Tab contents
                            div class="tab-content pt-3" id="walletTabsContent" {
                                div class="tab-pane fade show active" id="spendable" role="tabpanel" aria-labelledby="spendable-tab" {
                                    @if wallet_summary.spendable_utxos.is_empty() {
                                        p { "No spendable UTXOs available." }
                                    } @else {
                                        div class="table-responsive" {
                                            table class="table table-sm" {
                                                thead {
                                                    tr {
                                                        th { "Outpoint" }
                                                        th { "Amount (sats)" }
                                                    }
                                                }
                                                tbody {
                                                    @for utxo in &wallet_summary.spendable_utxos {
                                                        tr {
                                                            td { (format!("{}:{}", utxo.outpoint.txid, utxo.outpoint.vout)) }
                                                            td { (utxo.amount.to_sat()) }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                div class="tab-pane fade" id="unsigned" role="tabpanel" aria-labelledby="unsigned-tab" {
                                    @if wallet_summary.unsigned_peg_out_txos.is_empty() && wallet_summary.unsigned_change_utxos.is_empty() {
                                        p { "No unsigned outputs waiting for signatures." }
                                    } @else {
                                        div class="table-responsive" {
                                            table class="table table-sm" {
                                                thead {
                                                    tr {
                                                        th { "Type" }
                                                        th { "Outpoint" }
                                                        th { "Amount (sats)" }
                                                    }
                                                }
                                                tbody {
                                                    @for txo in &wallet_summary.unsigned_peg_out_txos {
                                                        tr {
                                                            td { "Peg-out" }
                                                            td { (format!("{}:{}", txo.outpoint.txid, txo.outpoint.vout)) }
                                                            td { (txo.amount.to_sat()) }
                                                        }
                                                    }
                                                    @for txo in &wallet_summary.unsigned_change_utxos {
                                                        tr {
                                                            td { "Change" }
                                                            td { (format!("{}:{}", txo.outpoint.txid, txo.outpoint.vout)) }
                                                            td { (txo.amount.to_sat()) }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                div class="tab-pane fade" id="unconfirmed" role="tabpanel" aria-labelledby="unconfirmed-tab" {
                                    @if wallet_summary.unconfirmed_peg_out_txos.is_empty() && wallet_summary.unconfirmed_change_utxos.is_empty() {
                                        p { "No unconfirmed outputs waiting for blockchain confirmation." }
                                    } @else {
                                        div class="table-responsive" {
                                            table class="table table-sm" {
                                                thead {
                                                    tr {
                                                        th { "Type" }
                                                        th { "Outpoint" }
                                                        th { "Amount (sats)" }
                                                    }
                                                }
                                                tbody {
                                                    @for txo in &wallet_summary.unconfirmed_peg_out_txos {
                                                        tr {
                                                            td { "Peg-out" }
                                                            td { (format!("{}:{}", txo.outpoint.txid, txo.outpoint.vout)) }
                                                            td { (txo.amount.to_sat()) }
                                                        }
                                                    }
                                                    @for txo in &wallet_summary.unconfirmed_change_utxos {
                                                        tr {
                                                            td { "Change" }
                                                            td { (format!("{}:{}", txo.outpoint.txid, txo.outpoint.vout)) }
                                                            td { (txo.amount.to_sat()) }
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
            }
        }
    }
}
