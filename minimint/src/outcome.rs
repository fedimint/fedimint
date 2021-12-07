use minimint_api::FederationModule;
use minimint_ln::contracts::ContractOutcome;
use minimint_ln::LightningModule;
use minimint_mint::SigResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum TransactionStatus {
    /// The transaction was successfully submitted
    AwaitingConsensus,
    /// The error state is only recorded if the error happens after consensus is achieved on the
    /// transaction. This should happen only rarely, e.g. on double spends since a basic validity
    /// check is performed on transaction submission.
    Error(String),
    /// The transaction was accepted and is now being processed
    Accepted {
        epoch: u64,
        outputs: Vec<OutputOutcome>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum OutputOutcome {
    Mint(Option<SigResponse>),
    // TODO: maybe include the transaction id eventually. But unclear how to propagate it cleanly right now.
    Wallet(()),
    LN(<LightningModule as FederationModule>::TxOutputOutcome),
}

pub trait Final {
    fn is_final(&self) -> bool;
}

impl Final for OutputOutcome {
    fn is_final(&self) -> bool {
        match self {
            OutputOutcome::Mint(Some(_)) => true,
            OutputOutcome::Mint(None) => false,
            OutputOutcome::Wallet(()) => true,
            OutputOutcome::LN(minimint_ln::OutputOutcome::Offer { .. }) => true,
            OutputOutcome::LN(minimint_ln::OutputOutcome::Contract { outcome, .. }) => {
                match outcome {
                    ContractOutcome::Account => true,
                    ContractOutcome::Incoming(
                        minimint_ln::contracts::incoming::DecryptedPreimage::Some(_),
                    ) => true,
                    ContractOutcome::Incoming(_) => false,
                    ContractOutcome::Outgoing => true,
                }
            }
        }
    }
}

impl Final for TransactionStatus {
    fn is_final(&self) -> bool {
        match self {
            TransactionStatus::AwaitingConsensus => false,
            TransactionStatus::Error(_) => true,
            TransactionStatus::Accepted { outputs, .. } => outputs.iter().all(|out| out.is_final()),
        }
    }
}
