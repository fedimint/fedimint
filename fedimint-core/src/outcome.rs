use fedimint_api::module::OutputOutcome;
// use fedimint_ln::contracts::incoming::OfferId;
// use fedimint_ln::contracts::{AccountContractOutcome, ContractOutcome, OutgoingContractOutcome};
// use fedimint_ln::contracts::{DecryptedPreimage, Preimage};
// use fedimint_ln::LightningModule;
// use fedimint_wallet::{PegOutOutcome, Wallet};
// use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub enum TransactionStatus {
    /// The rejected state is only recorded if the error happens after consensus is achieved on the
    /// transaction. This should happen only rarely, e.g. on double spends since a basic validity
    /// check is performed on transaction submission or on not having enough UTXOs to peg-out.
    Rejected(String),
    /// The transaction was accepted and is now being processed
    Accepted {
        epoch: u64,
        outputs: Vec<OutputOutcome>,
    },
}

pub trait Final {
    fn is_final(&self) -> bool;
}

impl Final for TransactionStatus {
    fn is_final(&self) -> bool {
        match self {
            TransactionStatus::Rejected(_) => true,
            TransactionStatus::Accepted { outputs, .. } => outputs.iter().all(|out| out.is_final()),
        }
    }
}

// impl TryIntoOutcome for PegOutOutcome {
//     fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
//         match common_outcome {
//             // OutputOutcome::Mint(_) => Err(CoreError::MismatchingVariant("wallet", "mint")),
//             OutputOutcome::Wallet(outcome) => Ok(outcome),
//             OutputOutcome::LN(_) => Err(CoreError::MismatchingVariant("wallet", "ln")),
//         }
//     }
// }

// impl TryIntoOutcome for fedimint_ln::OutputOutcome {
//     fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
//         match common_outcome {
//             // OutputOutcome::Mint(_) => Err(CoreError::MismatchingVariant("ln", "mint")),
//             OutputOutcome::Wallet(_) => Err(CoreError::MismatchingVariant("ln", "wallet")),
//             OutputOutcome::LN(outcome) => Ok(outcome),
//         }
//     }
// }

// impl TryIntoOutcome for Preimage {
//     fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
//         if let OutputOutcome::LN(fedimint_ln::OutputOutcome::Contract {
//             outcome: ContractOutcome::Incoming(decrypted_preimage),
//             ..
//         }) = common_outcome
//         {
//             match decrypted_preimage {
//                 DecryptedPreimage::Some(preimage) => Ok(preimage),
//                 DecryptedPreimage::Pending => Err(CoreError::PendingPreimage),
//                 _ => Err(CoreError::MismatchingVariant("ln::incoming", "other")),
//             }
//         } else {
//             Err(CoreError::MismatchingVariant("ln::incoming", "other"))
//         }
//     }
// }

// impl TryIntoOutcome for OfferId {
//     fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
//         if let OutputOutcome::LN(fedimint_ln::OutputOutcome::Offer { id }) = common_outcome {
//             Ok(id)
//         } else {
//             Err(CoreError::MismatchingVariant("ln::incoming", "other"))
//         }
//     }
// }

// impl TryIntoOutcome for AccountContractOutcome {
//     fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
//         if let OutputOutcome::LN(fedimint_ln::OutputOutcome::Contract {
//             outcome: ContractOutcome::Account(o),
//             ..
//         }) = common_outcome
//         {
//             Ok(o)
//         } else {
//             Err(CoreError::MismatchingVariant("ln::account", "other"))
//         }
//     }
// }

// impl TryIntoOutcome for OutgoingContractOutcome {
//     fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
//         if let OutputOutcome::LN(fedimint_ln::OutputOutcome::Contract {
//             outcome: ContractOutcome::Outgoing(o),
//             ..
//         }) = common_outcome
//         {
//             Ok(o)
//         } else {
//             Err(CoreError::MismatchingVariant("ln::outgoing", "other"))
//         }
//     }
// }
