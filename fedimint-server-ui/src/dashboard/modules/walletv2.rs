use maud::{Markup, html};

// Function to render the Wallet v2 module UI section
pub async fn render(wallet: &fedimint_walletv2_server::Wallet) -> Markup {
    let network = wallet.network_ui();
    let federation_wallet = wallet.federation_wallet_ui().await;
    let consensus_block_count = wallet.consensus_block_count_ui().await;
    let consensus_fee_rate = wallet.consensus_feerate_ui().await;
    let send_fee = wallet.send_fee_ui().await;
    let receive_fee = wallet.receive_fee_ui().await;
    let pending_transaction_chain = wallet.pending_transaction_chain_ui().await;
    let transaction_chain = wallet.transaction_chain_ui(20).await;
    let federation_address = wallet.federation_address_ui();
    let recovery_descriptor = wallet.export_descriptor_ui();
    let recovery_private_key = wallet.export_private_key_wif_ui();

    let total_pending_vbytes = pending_transaction_chain
        .iter()
        .map(|info| info.vbytes)
        .sum::<u64>();

    let total_pending_fee = pending_transaction_chain
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
                                        th { "Federation Address" }
                                        td {
                                            a href={ "https://mempool.space/address/" (federation_address) } class="btn btn-sm btn-outline-primary" target="_blank" {
                                                "mempool.space"
                                            }
                                        }
                                    }
                                    tr {
                                        th { "Funding Transaction" }
                                        td {
                                            a href={ "https://mempool.space/tx/" (wallet.txid) } class="btn btn-sm btn-outline-primary" target="_blank" {
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


                        @if !pending_transaction_chain.is_empty() {
                            div class="mb-4" {
                                h5 { "Pending Transaction Chain" }
                                @if consensus_block_count > pending_transaction_chain.last().unwrap().created + 18 {
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
                                        @for tx in pending_transaction_chain{
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
                                                td { (tx.feerate) }
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


                        @if !transaction_chain.is_empty() {
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
                                        @for tx in transaction_chain {
                                            tr {
                                                td { (tx.index) }
                                                td {
                                                    @if tx.output > tx.input {
                                                        span class="text-success" { "+" (tx.output - tx.input) }
                                                    } @else {
                                                        span class="text-danger" { "-" (tx.input - tx.output) }
                                                    }
                                                }
                                                td { (tx.fee.to_sat()) }
                                                td { (tx.vbytes) }
                                                td { (tx.feerate) }
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
                                            strong { "How to recover funds: " }
                                            "Import the descriptor into a wallet like Bitcoin Core or Sparrow, then import your private key. Once a threshold of guardians have done this, you can collaboratively sign a transaction to recover the funds."
                                        }

                                        div class="mb-3" {
                                            p class="mb-2" { strong { "Descriptor" } " (identical for all guardians)" }
                                            div class="alert alert-info text-break" style="word-break: break-all;" {
                                                (recovery_descriptor)
                                            }
                                        }

                                        div class="mb-3" {
                                            p class="mb-2" { strong { "Private Key" } " (Wallet Import Format)" }
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
