use maud::{Markup, html};

// Function to render the Wallet module UI section
pub async fn render(wallet: &fedimint_wallet_server::Wallet) -> Markup {
    let network = wallet.network_ui();
    let consensus_block_count = wallet.consensus_block_count_ui().await;
    let consensus_fee_rate = wallet.consensus_feerate_ui().await;
    let wallet_summary = wallet.get_wallet_summary_ui().await;
    let total_spendable = wallet_summary.total_spendable_balance().to_sat();
    let total_unsigned_change = wallet_summary.total_unsigned_change_balance().to_sat();
    let total_unconfirmed_change = wallet_summary.total_unconfirmed_change_balance().to_sat();
    let total_available = total_spendable + total_unconfirmed_change + total_unsigned_change;
    let total_unsigned_outgoing = wallet_summary.total_unsigned_peg_out_balance().to_sat();
    let total_unconfirmed_outgoing = wallet_summary.total_unconfirmed_peg_out_balance().to_sat();

    html! {
        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { "Wallet" }
                    div class="card-body" {
                        table class="table mb-4" {
                            tr {
                                th { "Network" }
                                td { (network.to_string()) }
                            }
                            tr {
                                th { "Consensus Block Count" }
                                td { (consensus_block_count) }
                            }
                            tr {
                                th { "Consensus Fee Rate" }
                                td { (consensus_fee_rate.sats_per_kvb) " sats/kvB" }
                            }
                            tr {
                                th { "Spendable Amount" }
                                td { (total_spendable) " sats" }
                            }
                            tr {
                                th { "Unsigned Change Amount" }
                                td { (total_unsigned_change) " sats" }
                            }
                            tr {
                                th { "Unconfirmed Change Amount" }
                                td { (total_unconfirmed_change) " sats" }
                            }
                            tr {
                                th { "Total Amount in Custody" }
                                td { (total_available) " sats" }
                            }
                            tr {
                                th { "Unsigned Outgoing Amount" }
                                td { (total_unsigned_outgoing) " sats" }
                            }
                            tr {
                                th { "Unconfirmed Outgoing Amount" }
                                td { (total_unconfirmed_outgoing) " sats" }
                            }
                        }

                        // Collapsible info section
                        div class="mb-4" {
                            p {
                                button class="btn btn-sm btn-outline-primary" type="button" data-bs-toggle="collapse" data-bs-target="#balanceInfo" aria-expanded="false" aria-controls="balanceInfo" {
                                    "What do these amounts mean? "
                                    i class="bi bi-info-circle" {}
                                }
                            }
                            div class="collapse" id="balanceInfo" {
                                div class="alert alert-info" {
                                    dl class="row mb-0" {
                                        dt class="col-sm-3" { "Spendable Amount" }
                                        dd class="col-sm-9" { "UTXOs that are confirmed and are available to be spend by your users." }

                                        dt class="col-sm-3" { "Change Amounts" }
                                        dd class="col-sm-9" {
                                            p class="mb-1" { strong { "Unsigned: " } "Change outputs from pegout transactions still waiting for guardian signatures." }
                                            p class="mb-0" { strong { "Unconfirmed: " } "Change outputs with threshold of signatures, waiting for blockchain confirmations." }
                                        }

                                        dt class="col-sm-3" { "Total Amount in Custody" }
                                        dd class="col-sm-9" {
                                            "Sum of Spendable Amount and both unsigned and unconfirmed change amounts. This represents all funds that will eventually be available to you once all transactions are confirmed."
                                        }

                                        dt class="col-sm-3" { "Outgoing Amounts" }
                                        dd class="col-sm-9" {
                                            p class="mb-1" { strong { "Unsigned: " } "Pegout outputs from pegout transactions still waiting for guardian signatures." }
                                            p class="mb-0" { strong { "Unconfirmed: " } "Pegout outputs with threshold of signatures, waiting for blockchain confirmations." }
                                        }
                                    }
                                }
                            }
                        }

                        // UTXO Tables
                        div class="mb-4" {
                            @if !wallet_summary.unconfirmed_peg_out_txos.is_empty() {
                                div class="mb-4" {
                                    h5 { "Unconfirmed Pegout UTXOs" }
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
                                    h5 { "Unconfirmed Change UTXOs" }
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
