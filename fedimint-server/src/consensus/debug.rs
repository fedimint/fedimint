use std::fmt::Write;

use fedimint_core::transaction::Transaction;

use crate::{ConsensusItem, HbbftConsensusOutcome};

/// outputs a useful debug message for epochs indicating what happened
pub fn epoch_message(consensus: &HbbftConsensusOutcome) -> String {
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
        ConsensusItem::EpochOutcomeSignatureShare(_) => "Outcome Signature".to_string(),
        ConsensusItem::ClientConfigSignatureShare(_) => "Client Config Signature".to_string(),
        // TODO: make this nice again
        ConsensusItem::Module(mci) => {
            format!("Module CI: module={} ci={}", mci.module_instance_id(), mci)
        }
        ConsensusItem::Transaction(Transaction {
            inputs, outputs, ..
        }) => {
            let mut tx_debug = "Transaction".to_string();
            for input in inputs.iter() {
                // TODO: add pretty print fn to interface
                write!(tx_debug, "\n    Input: {}", input).unwrap();
            }
            for output in outputs.iter() {
                write!(tx_debug, "\n    Output: {}", output).unwrap();
            }
            tx_debug
        }
    }
}
