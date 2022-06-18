use minimint_api::FederationModule;
use minimint_ln::contracts::incoming::{DecryptedPreimage, OfferId, Preimage};
use minimint_ln::contracts::{AccountContractOutcome, ContractOutcome, OutgoingContractOutcome};
use minimint_ln::LightningModule;
use minimint_mint::SigResponse;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum TransactionStatus {
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

pub trait TryIntoOutcome: Sized {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, MismatchingVariant>;
}

impl OutputOutcome {
    pub fn try_into_variant<T: TryIntoOutcome>(self) -> Result<T, MismatchingVariant> {
        T::try_into_outcome(self)
    }
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
                    ContractOutcome::Account(_) => true,
                    ContractOutcome::Incoming(
                        minimint_ln::contracts::incoming::DecryptedPreimage::Some(_),
                    ) => true,
                    ContractOutcome::Incoming(_) => false,
                    ContractOutcome::Outgoing(_) => true,
                }
            }
        }
    }
}

impl Final for TransactionStatus {
    fn is_final(&self) -> bool {
        match self {
            TransactionStatus::Error(_) => true,
            TransactionStatus::Accepted { outputs, .. } => outputs.iter().all(|out| out.is_final()),
        }
    }
}

#[derive(Debug, Error)]
#[error("Mismatching outcome variant: expected {0}, got {1}")]
pub struct MismatchingVariant(&'static str, &'static str);

impl TryIntoOutcome for Option<SigResponse> {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, MismatchingVariant> {
        match common_outcome {
            OutputOutcome::Mint(outcome) => Ok(outcome),
            OutputOutcome::Wallet(_) => Err(MismatchingVariant("mint", "wallet")),
            OutputOutcome::LN(_) => Err(MismatchingVariant("mint", "ln")),
        }
    }
}

impl TryIntoOutcome for () {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, MismatchingVariant> {
        match common_outcome {
            OutputOutcome::Mint(_) => Err(MismatchingVariant("wallet", "mint")),
            OutputOutcome::Wallet(outcome) => Ok(outcome),
            OutputOutcome::LN(_) => Err(MismatchingVariant("wallet", "ln")),
        }
    }
}

impl TryIntoOutcome for minimint_ln::OutputOutcome {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, MismatchingVariant> {
        match common_outcome {
            OutputOutcome::Mint(_) => Err(MismatchingVariant("ln", "mint")),
            OutputOutcome::Wallet(_) => Err(MismatchingVariant("ln", "wallet")),
            OutputOutcome::LN(outcome) => Ok(outcome),
        }
    }
}

impl TryIntoOutcome for Preimage {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, MismatchingVariant> {
        if let OutputOutcome::LN(minimint_ln::OutputOutcome::Contract {
            outcome: ContractOutcome::Incoming(DecryptedPreimage::Some(preimage)),
            ..
        }) = common_outcome
        {
            Ok(preimage)
        } else {
            Err(MismatchingVariant("ln::incoming", "other"))
        }
    }
}

impl TryIntoOutcome for OfferId {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, MismatchingVariant> {
        if let OutputOutcome::LN(minimint_ln::OutputOutcome::Offer { id }) = common_outcome {
            Ok(id)
        } else {
            Err(MismatchingVariant("ln::incoming", "other"))
        }
    }
}

impl TryIntoOutcome for AccountContractOutcome {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, MismatchingVariant> {
        if let OutputOutcome::LN(minimint_ln::OutputOutcome::Contract {
            outcome: ContractOutcome::Account(o),
            ..
        }) = common_outcome
        {
            Ok(o)
        } else {
            Err(MismatchingVariant("ln::account", "other"))
        }
    }
}

impl TryIntoOutcome for OutgoingContractOutcome {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, MismatchingVariant> {
        if let OutputOutcome::LN(minimint_ln::OutputOutcome::Contract {
            outcome: ContractOutcome::Outgoing(o),
            ..
        }) = common_outcome
        {
            Ok(o)
        } else {
            Err(MismatchingVariant("ln::outgoing", "other"))
        }
    }
}
