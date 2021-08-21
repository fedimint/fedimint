use crate::SigResponse;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct TransactionOutcome {
    pub tx_hash: crate::TransactionId,
    pub status: TransactionStatus,
    pub outputs: BTreeMap<usize, Option<OutputOutcome>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum TransactionStatus {
    /// The transaction was successfully submitted
    AwaitingConsensus,
    // FIXME: consider using concrete error type? Otoh this should never happen and it would destroy the module structure (pulling all errors in here)
    /// The error state is only recorded if the error happens after consensus is achieved on the
    /// transaction. This should happen only rarely, e.g. on double spends since a basic validity
    /// check is performed on transaction submission.
    Error(String),
    /// The transaction was accepted and is now being processed
    Accepted,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum OutputOutcome {
    Coins { blind_signature: SigResponse },
    // TODO: maybe include the transaction id eventually. But unclear how to propagate it cleanly right now.
    PegOut,
}

impl TransactionOutcome {
    pub fn is_final(&self) -> bool {
        self.status == TransactionStatus::Accepted && self.outputs.values().all(Option::is_some)
    }
}
