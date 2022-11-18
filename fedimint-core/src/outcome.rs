use fedimint_api::FederationModule;
use fedimint_ln::contracts::incoming::OfferId;
use fedimint_ln::contracts::{AccountContractOutcome, ContractOutcome, OutgoingContractOutcome};
use fedimint_ln::contracts::{DecryptedPreimage, Preimage};
use fedimint_ln::LightningModule;
use fedimint_mint::{Mint, MintOutputOutcome};
use fedimint_wallet::{Wallet, WalletOutputOutcome};
use serde::{Deserialize, Serialize};

use crate::CoreError;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum OutputOutcome {
    Mint(<Mint as FederationModule>::TxOutputOutcome),
    Wallet(<Wallet as FederationModule>::TxOutputOutcome),
    LN(<LightningModule as FederationModule>::TxOutputOutcome),
}

pub trait Final {
    fn is_final(&self) -> bool;
}

pub trait TryIntoOutcome: Sized {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError>;
}

impl OutputOutcome {
    pub fn try_into_variant<T: TryIntoOutcome>(self) -> Result<T, CoreError> {
        T::try_into_outcome(self)
    }
}

impl Final for OutputOutcome {
    fn is_final(&self) -> bool {
        match self {
            OutputOutcome::Mint(MintOutputOutcome(Some(_))) => true,
            OutputOutcome::Mint(MintOutputOutcome(None)) => false,
            OutputOutcome::Wallet(_) => true,
            OutputOutcome::LN(fedimint_ln::LightningOutputOutcome::Offer { .. }) => true,
            OutputOutcome::LN(fedimint_ln::LightningOutputOutcome::Contract {
                outcome, ..
            }) => match outcome {
                ContractOutcome::Account(_) => true,
                ContractOutcome::Incoming(DecryptedPreimage::Some(_)) => true,
                ContractOutcome::Incoming(_) => false,
                ContractOutcome::Outgoing(_) => true,
            },
        }
    }
}

impl Final for TransactionStatus {
    fn is_final(&self) -> bool {
        match self {
            TransactionStatus::Rejected(_) => true,
            TransactionStatus::Accepted { outputs, .. } => outputs.iter().all(|out| out.is_final()),
        }
    }
}

impl TryIntoOutcome for MintOutputOutcome {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
        match common_outcome {
            OutputOutcome::Mint(outcome) => Ok(outcome),
            OutputOutcome::Wallet(_) => Err(CoreError::MismatchingVariant("mint", "wallet")),
            OutputOutcome::LN(_) => Err(CoreError::MismatchingVariant("mint", "ln")),
        }
    }
}

impl TryIntoOutcome for WalletOutputOutcome {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
        match common_outcome {
            OutputOutcome::Mint(_) => Err(CoreError::MismatchingVariant("wallet", "mint")),
            OutputOutcome::Wallet(outcome) => Ok(outcome),
            OutputOutcome::LN(_) => Err(CoreError::MismatchingVariant("wallet", "ln")),
        }
    }
}

impl TryIntoOutcome for fedimint_ln::LightningOutputOutcome {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
        match common_outcome {
            OutputOutcome::Mint(_) => Err(CoreError::MismatchingVariant("ln", "mint")),
            OutputOutcome::Wallet(_) => Err(CoreError::MismatchingVariant("ln", "wallet")),
            OutputOutcome::LN(outcome) => Ok(outcome),
        }
    }
}

impl TryIntoOutcome for Preimage {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
        if let OutputOutcome::LN(fedimint_ln::LightningOutputOutcome::Contract {
            outcome: ContractOutcome::Incoming(decrypted_preimage),
            ..
        }) = common_outcome
        {
            match decrypted_preimage {
                DecryptedPreimage::Some(preimage) => Ok(preimage),
                DecryptedPreimage::Pending => Err(CoreError::PendingPreimage),
                _ => Err(CoreError::MismatchingVariant("ln::incoming", "other")),
            }
        } else {
            Err(CoreError::MismatchingVariant("ln::incoming", "other"))
        }
    }
}

impl TryIntoOutcome for OfferId {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
        if let OutputOutcome::LN(fedimint_ln::LightningOutputOutcome::Offer { id }) = common_outcome
        {
            Ok(id)
        } else {
            Err(CoreError::MismatchingVariant("ln::incoming", "other"))
        }
    }
}

impl TryIntoOutcome for AccountContractOutcome {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
        if let OutputOutcome::LN(fedimint_ln::LightningOutputOutcome::Contract {
            outcome: ContractOutcome::Account(o),
            ..
        }) = common_outcome
        {
            Ok(o)
        } else {
            Err(CoreError::MismatchingVariant("ln::account", "other"))
        }
    }
}

impl TryIntoOutcome for OutgoingContractOutcome {
    fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
        if let OutputOutcome::LN(fedimint_ln::LightningOutputOutcome::Contract {
            outcome: ContractOutcome::Outgoing(o),
            ..
        }) = common_outcome
        {
            Ok(o)
        } else {
            Err(CoreError::MismatchingVariant("ln::outgoing", "other"))
        }
    }
}
