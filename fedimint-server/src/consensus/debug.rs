use std::fmt::Write;

use fedimint_core::transaction::Transaction;

use crate::ConsensusItem;

pub fn item_message(item: &ConsensusItem) -> String {
    match item {
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
                write!(tx_debug, "\n    Input: {input}").unwrap();
            }
            for output in outputs.iter() {
                write!(tx_debug, "\n    Output: {output}").unwrap();
            }
            tx_debug
        }
    }
}
