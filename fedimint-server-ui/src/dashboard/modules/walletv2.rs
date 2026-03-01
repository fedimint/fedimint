use maud::{Markup, html};

// Function to render the Wallet v2 module UI section
pub async fn render(wallet: &fedimint_walletv2_server::Wallet) -> Markup {
    let network = wallet.network_ui();
    let federation_wallet = wallet.federation_wallet_ui().await;
    let consensus_block_count = wallet.consensus_block_count_ui().await;
    let consensus_fee_rate = wallet.consensus_feerate_ui().await;
    let send_fee = wallet.send_fee_ui().await;
    let receive_fee = wallet.receive_fee_ui().await;
    let pending_tx_chain = wallet.pending_tx_chain_ui().await;
    let tx_chain = wallet.tx_chain_ui(20).await;
    let recovery_keys = wallet.recovery_keys_ui().await;

    let total_pending_vbytes = pending_tx_chain.iter().map(|info| info.vbytes).sum::<u64>();

    let total_pending_fee = pending_tx_chain
        .iter()
        .map(|info| info.fee.to_sat())
        .sum::<u64>();

    html! {
        div class="row gy-4 mt-2" {
            div class="col-12" {
                div class="card h-100" {
                    div class="card-header dashboard-header" { "Wallet V2" }
                    div class="card-body" {
                        div class="mb-4" {
                            table class="table" {
                                tr {
                                    th { "Network" }
                                    td { (network) }
                                }
                                @if let Some(wallet) = federation_wallet {
                                    tr {
                                        th { "Value in Custody" }
                                        td { (format!("{:.8} BTC", wallet.value.to_btc())) }
                                    }
                                    tr {
                                        th { "Transaction Chain Tip" }
                                        td {
                                            a href={ "https://mempool.space/tx/" (wallet.outpoint.txid) } class="btn btn-sm btn-outline-primary" target="_blank" {
                                                "mempool.space"
                                            }
                                        }
                                    }
                                }
                                tr {
                                    th { "Consensus Block Count" }
                                    td { (consensus_block_count) }
                                }
                                tr {
                                    th { "Consensus Fee Rate" }
                                    td {
                                        @if let Some(fee_rate) = consensus_fee_rate {
                                            (fee_rate) " sat/vbyte"
                                        } @else {
                                            "No consensus fee rate available"
                                        }
                                    }
                                }
                                tr {
                                    th { "Send Fee" }
                                    td {
                                        @if let Some(fee) = send_fee {
                                            (fee.to_sat()) " sats"
                                        } @else {
                                            "No send fee available"
                                        }
                                    }
                                }
                                tr {
                                    th { "Receive Fee" }
                                    td {
                                        @if let Some(fee) = receive_fee {
                                            (fee.to_sat()) " sats"
                                        } @else {
                                            "No receive fee available"
                                        }
                                    }
                                }
                            }
                        }


                        @if !pending_tx_chain.is_empty() {
                            div class="mb-4" {
                                h5 { "Pending Transaction Chain" }
                                @if consensus_block_count > pending_tx_chain.last().unwrap().created + 18 {
                                    div class="alert alert-danger" role="alert" {
                                        "Warning: Transaction has been pending for more than 18 blocks!"
                                    }
                                }

                                table class="table" {
                                    thead {
                                        tr {
                                            th { "Index" }
                                            th { "Value in Custody" }
                                            th { "Fee" }
                                            th { "vBytes" }
                                            th { "Feerate" }
                                            th { "Age" }
                                            th { "Transaction" }
                                        }
                                    }
                                    tbody {
                                        @for tx in pending_tx_chain{
                                            tr {
                                                td { (tx.index) }
                                                td {
                                                    @if tx.output >= tx.input {
                                                        span class="text-success" { "+" (tx.output - tx.input) }
                                                    } @else {
                                                        span class="text-danger" { "-" (tx.input - tx.output) }
                                                    }
                                                }
                                                td { (tx.fee.to_sat()) }
                                                td { (tx.vbytes) }
                                                td { (tx.feerate()) }
                                                td { (consensus_block_count.saturating_sub(tx.created)) }
                                                td {
                                                    a href={ "https://mempool.space/tx/" (tx.txid) } class="btn btn-sm btn-outline-primary" target="_blank" {
                                                        "mempool.space"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                div class="alert alert-info" role="alert" {
                                    "Total feerate of pending chain: " strong { (total_pending_fee / total_pending_vbytes) " sat/vbyte" }
                                }
                            }
                        }


                        @if !tx_chain.is_empty() {
                            div class="mb-4" {
                                h5 { "Total Transaction Chain" }
                                table class="table" {
                                    thead {
                                        tr {
                                            th { "Index" }
                                            th { "Value in Custody" }
                                            th { "Fee" }
                                            th { "vBytes" }
                                            th { "Feerate" }
                                            th { "Age" }
                                            th { "Transaction" }
                                        }
                                    }
                                    tbody {
                                        @for tx in tx_chain {
                                            tr {
                                                td { (tx.index) }
                                                td {
                                                    @if tx.output >= tx.input {
                                                        span class="text-success" { "+" (tx.output - tx.input) }
                                                    } @else {
                                                        span class="text-danger" { "-" (tx.input - tx.output) }
                                                    }
                                                }
                                                td { (tx.fee.to_sat()) }
                                                td { (tx.vbytes) }
                                                td { (tx.feerate()) }
                                                td { (consensus_block_count.saturating_sub(tx.created)) }
                                                td {
                                                    a href={ "https://mempool.space/tx/" (tx.txid) } class="btn btn-sm btn-outline-primary" target="_blank" {
                                                        "mempool.space"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        @if let Some((recovery_public_keys, recovery_private_key)) = &recovery_keys {
                            // Federation Shutdown accordion
                            div class="accordion mt-4" id="shutdownAccordion" {
                                div class="accordion-item" {
                                    h2 class="accordion-header" {
                                        button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#shutdownCollapse" aria-expanded="false" aria-controls="shutdownCollapse" {
                                            "Federation Shutdown"
                                        }
                                    }
                                    div id="shutdownCollapse" class="accordion-collapse collapse" data-bs-parent="#shutdownAccordion" {
                                        div class="accordion-body" {
                                            div class="alert alert-info mb-3" {
                                                "To recover your remaining funds after decommissioning the federation, please go to the "
                                                a href="https://recovery.fedimint.org" target="_blank" { "recovery tool" }
                                                " and follow the instructions."
                                            }

                                            div class="alert alert-warning mb-3" {
                                                "The recovery keys change with every transaction. All guardians must be fully synced before extracting keys, otherwise the keys will not match the current federation UTXO."
                                            }

                                            div class="mb-3" {
                                                table class="table table-sm" {
                                                    thead {
                                                        tr {
                                                            th { "Guardian" }
                                                            th { "Public Key (hex)" }
                                                        }
                                                    }
                                                    tbody {
                                                        @for (peer, pk) in recovery_public_keys {
                                                            tr {
                                                                td { (peer) }
                                                                td class="text-break" style="word-break: break-all; font-family: monospace;" { (pk) }
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            div class="mb-3" {
                                                p class="mb-2" { strong { "Your Private Key (WIF)" } }
                                                div class="alert alert-danger text-break" style="word-break: break-all;" {
                                                    (recovery_private_key)
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
