use crate::{ConsensusItem, ConsensusOutcome};
use minimint_core::modules::ln::contracts::Contract;
use minimint_core::modules::ln::{ContractOrOfferOutput, ContractOutput, DecryptionShareCI};
use minimint_core::modules::mint::PartiallySignedRequest;
use minimint_core::transaction::{Input, Output, Transaction};
use minimint_wallet::{PegOutSignatureItem, RoundConsensusItem, WalletConsensusItem};
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
        ConsensusItem::Wallet(WalletConsensusItem::RoundConsensus(RoundConsensusItem {
            block_height,
            ..
        })) => format!("Wallet Block Height {}", block_height),
        ConsensusItem::Wallet(WalletConsensusItem::PegOutSignature(PegOutSignatureItem {
            txid,
            ..
        })) => format!("Wallet Peg Out PSBT {:.8}", txid),
        ConsensusItem::Mint(PartiallySignedRequest {
            out_point,
            partial_signature,
        }) => {
            format!(
                "Mint Signed Coins {} with TxId {:.8}",
                partial_signature.0.amount(),
                out_point.txid
            )
        }
        ConsensusItem::LN(DecryptionShareCI { contract_id, .. }) => {
            format!("LN Decrytion Share for contract {:.8}", contract_id)
        }
        ConsensusItem::Transaction(Transaction {
            inputs, outputs, ..
        }) => {
            let mut tx_debug = "Transaction".to_string();
            for input in inputs.iter() {
                let input_debug = match input {
                    Input::Mint(t) => format!("Mint Coins {}", t.amount()),
                    Input::Wallet(t) => {
                        format!("Wallet PegIn with TxId {:.8}", t.outpoint().txid)
                    }
                    Input::LN(t) => {
                        format!("LN Contract {} with id {:.8}", t.amount, t.contract_id)
                    }
                };
                write!(tx_debug, "\n    Input: {}", input_debug).unwrap();
            }
            for output in outputs.iter() {
                let output_debug = match output {
                    Output::Mint(t) => format!("Mint Coins {}", t.amount()),
                    Output::Wallet(t) => {
                        format!("Wallet PegOut {} to address {:.8}", t.amount, t.recipient)
                    }
                    Output::LN(ContractOrOfferOutput::Offer(o)) => {
                        format!("LN Offer for {} with hash {:.8}", o.amount, o.hash)
                    }
                    Output::LN(ContractOrOfferOutput::Contract(ContractOutput {
                        amount,
                        contract,
                    })) => match contract {
                        Contract::Account(a) => {
                            format!("LN Account Contract for {} key {:.8}", amount, a.key)
                        }
                        Contract::Incoming(a) => {
                            format!("LN Incoming Contract for {} hash {:.8}", amount, a.hash)
                        }
                        Contract::Outgoing(a) => {
                            format!("LN Outgoing Contract for {} hash {:.8}", amount, a.hash)
                        }
                    },
                };
                write!(tx_debug, "\n    Output: {}", output_debug).unwrap();
            }
            tx_debug
        }
    }
}
