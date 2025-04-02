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
                        table class="table mb-4" {
                            tr {
                                th { "Consensus Block Count" }
                                td { (consensus_block_count) }
                            }
                            tr {
                                th { "Consensus Fee Rate" }
                                td { (consensus_fee_rate.sats_per_kvb) " sats/kvB" }
                            }
                            tr {
                                th { "Spendable Balance" }
                                td { (total_spendable) " sats" }
                            }
                            tr {
                                th { "Pending Outgoing" }
                                td { (total_pending_outgoing) " sats" }
                            }
                            tr {
                                th { "Pending Change" }
                                td { (total_pending_change) " sats" }
                            }
                        }

                        // UTXO Tables
                        div class="mb-4" {
                            // Pending Peg-out UTXOs Table
                            @if !wallet_summary.unconfirmed_peg_out_txos.is_empty() {
                                div class="mb-4" {
                                    h5 { "Pending Peg-out UTXOs" }
                                    div class="table-responsive" {
                                        table class="table table-sm" {
                                            thead {
                                                tr {
                                                    th { "Amount (sats)" }
                                                    th { "Transaction" }
                                                    th { "Vout" }
                                                }
                                            }
                                            tbody {
                                                @for txo in &wallet_summary.unconfirmed_peg_out_txos {
                                                    tr {
                                                        td { (txo.amount.to_sat()) }
                                                        td {
                                                            a href={ "https://mempool.space/tx/" (txo.outpoint.txid) } class="btn btn-sm btn-outline-primary" target="_blank" {
                                                                "mempool.space"
                                                            }
                                                        }
                                                        td { (txo.outpoint.vout) }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Pending Change UTXOs Table
                            @if !wallet_summary.unconfirmed_change_utxos.is_empty() {
                                div class="mb-4" {
                                    h5 { "Pending Change UTXOs" }
                                    div class="table-responsive" {
                                        table class="table table-sm" {
                                            thead {
                                                tr {
                                                    th { "Amount (sats)" }
                                                    th { "Transaction" }
                                                    th { "Vout" }
                                                }
                                            }
                                            tbody {
                                                @for txo in &wallet_summary.unconfirmed_change_utxos {
                                                    tr {
                                                        td { (txo.amount.to_sat()) }
                                                        td {
                                                            a href={ "https://mempool.space/tx/" (txo.outpoint.txid) } class="btn btn-sm btn-outline-primary" target="_blank" {
                                                                "mempool.space"
                                                            }
                                                        }
                                                        td { (txo.outpoint.vout) }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Spendable UTXOs Table
                            @if !wallet_summary.spendable_utxos.is_empty() {
                                div class="mb-4" {
                                    h5 { "Spendable UTXOs" }
                                    div class="table-responsive" {
                                        table class="table table-sm" {
                                            thead {
                                                tr {
                                                    th { "Amount (sats)" }
                                                    th { "Transaction" }
                                                    th { "Vout" }
                                                }
                                            }
                                            tbody {
                                                @for utxo in &wallet_summary.spendable_utxos {
                                                    tr {
                                                        td { (utxo.amount.to_sat()) }
                                                        td {
                                                            a href={ "https://mempool.space/tx/" (utxo.outpoint.txid) } class="btn btn-sm btn-outline-primary" target="_blank" {
                                                                "mempool.space"
                                                            }
                                                        }
                                                        td { (utxo.outpoint.vout) }
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
