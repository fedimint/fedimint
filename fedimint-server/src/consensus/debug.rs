use crate::{ConsensusItem, ConsensusOutcome};
use fedimint_core::modules::ln::contracts::Contract;
use fedimint_core::modules::ln::{ContractOrOfferOutput, ContractOutput, DecryptionShareCI};
use fedimint_core::modules::mint::PartiallySignedRequest;
use fedimint_core::transaction::{Input, Output, Transaction};
use fedimint_wallet::{PegOutSignatureItem, RoundConsensusItem, WalletConsensusItem};
use std::fmt::Write;

/// outputs a useful debug message for epochs indicating what happened
pub fn epoch_message(consensus: &ConsensusOutcome) -> String {
    let peers = consensus.contributions.keys();
    let mut debug = format!("\n- Epoch: {} {:?} -", consensus.epoch, peers);

    for (peer, items) in consensus.contributions.iter() {
        for item in items {
            let item_debug = item_message(item);
            write!(debug, "\n  Peer {}: {}", peer, item_debug).unwrap();
        }
    }
    debug
}

fn item_message(item: &ConsensusItem) -> String {
    match item {
        ConsensusItem::EpochInfo(_) => "Outcome Signature".to_string(),
        ConsensusItem::Wallet(WalletConsensusItem::RoundConsensus(RoundConsensusItem {
            block_height,
            ..
        })) => format!("Wallet Block Height {}", block_height),
        ConsensusItem::Wallet(WalletConsensusItem::PegOutSignature(PegOutSignatureItem {
            txid,
            ..
        })) => format!("Wallet Peg Out PSBT {}", txid),
        ConsensusItem::Mint(PartiallySignedRequest {
            out_point,
            partial_signature,
        }) => {
            format!(
                "Mint Signed Coins {} with TxId {}",
                partial_signature.0.total_amount(),
                out_point.txid
            )
        }
        ConsensusItem::LN(DecryptionShareCI { contract_id, .. }) => {
            format!("LN Decryption Share for contract {}", contract_id)
        }
        ConsensusItem::Transaction(Transaction {
            inputs, outputs, ..
        }) => {
            let mut tx_debug = "Transaction".to_string();
            for input in inputs.iter() {
                let input_debug = match input {
                    Input::Mint(t) => format!("Mint Coins {}", t.total_amount()),
                    Input::Wallet(t) => {
                        format!("Wallet PegIn with TxId {}", t.outpoint().txid)
                    }
                    Input::LN(t) => {
                        format!("LN Contract {} with id {}", t.amount, t.contract_id)
                    }
                };
                write!(tx_debug, "\n    Input: {}", input_debug).unwrap();
            }
            for output in outputs.iter() {
                let output_debug = match output {
                    Output::Mint(t) => format!("Mint Coins {}", t.total_amount()),
                    Output::Wallet(t) => {
                        format!("Wallet PegOut {} to address {}", t.amount, t.recipient)
                    }
                    Output::LN(ContractOrOfferOutput::Offer(o)) => {
                        format!("LN Offer for {} with hash {}", o.amount, o.hash)
                    }
                    Output::LN(ContractOrOfferOutput::CancelOutgoing { contract, .. }) => {
                        format!("LN Outgoing contract {} cancellation", contract)
                    }
                    Output::LN(ContractOrOfferOutput::Contract(ContractOutput {
                        amount,
                        contract,
                    })) => match contract {
                        Contract::Account(a) => {
                            format!("LN Account Contract for {} key {}", amount, a.key)
                        }
                        Contract::Incoming(a) => {
                            format!("LN Incoming Contract for {} hash {}", amount, a.hash)
                        }
                        Contract::Outgoing(a) => {
                            format!("LN Outgoing Contract for {} hash {}", amount, a.hash)
                        }
                    },
                };
                write!(tx_debug, "\n    Output: {}", output_debug).unwrap();
            }
            tx_debug
        }
    }
}
