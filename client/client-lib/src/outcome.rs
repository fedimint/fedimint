


pub mod legacy {
    use fedimint_api::core::{
        Decoder, LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
        LEGACY_HARDCODED_INSTANCE_ID_WALLET,
    };
    use fedimint_api::encoding::{Decodable, Encodable};
    use fedimint_api::ServerModule;
    use fedimint_core::CoreError;
    use fedimint_ln::contracts::incoming::OfferId;
    use fedimint_ln::contracts::{
        AccountContractOutcome, ContractOutcome, DecryptedPreimage, OutgoingContractOutcome,
        Preimage,
    };
    use fedimint_ln::{Lightning, LightningOutputOutcome};
    use fedimint_mint::{Mint, MintOutputOutcome};
    use fedimint_wallet::{Wallet, WalletOutputOutcome};

    #[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
    pub enum OutputOutcome {
        Mint(<<Mint as ServerModule>::Decoder as Decoder>::OutputOutcome),
        Wallet(<<Wallet as ServerModule>::Decoder as Decoder>::OutputOutcome),
        LN(<<Lightning as ServerModule>::Decoder as Decoder>::OutputOutcome),
    }

    impl From<fedimint_api::core::DynOutputOutcome> for OutputOutcome {
        fn from(oo: fedimint_api::core::DynOutputOutcome) -> Self {
            match oo.module_instance_id() {
                LEGACY_HARDCODED_INSTANCE_ID_LN => OutputOutcome::LN(
                    oo.as_any()
                        .downcast_ref::<LightningOutputOutcome>()
                        .expect("Module key matches")
                        .clone(),
                ),
                LEGACY_HARDCODED_INSTANCE_ID_MINT => OutputOutcome::Mint(
                    oo.as_any()
                        .downcast_ref::<MintOutputOutcome>()
                        .expect("Module key matches")
                        .clone(),
                ),
                LEGACY_HARDCODED_INSTANCE_ID_WALLET => OutputOutcome::Wallet(
                    oo.as_any()
                        .downcast_ref::<WalletOutputOutcome>()
                        .expect("Module key matches")
                        .clone(),
                ),
                _ => panic!("Unknown Module"),
            }
        }
    }

    pub trait TryIntoOutcome: Sized {
        fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError>;
    }

    impl OutputOutcome {
        pub fn try_into_variant<T: TryIntoOutcome>(self) -> Result<T, CoreError> {
            T::try_into_outcome(self)
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
            if let OutputOutcome::LN(fedimint_ln::LightningOutputOutcome::Offer { id }) =
                common_outcome
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
}
