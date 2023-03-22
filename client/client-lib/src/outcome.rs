pub mod legacy {
    use fedimint_core::api::OutputOutcomeError;
    use fedimint_core::core::{
        LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
        LEGACY_HARDCODED_INSTANCE_ID_WALLET,
    };
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::ModuleCommon;
    use fedimint_core::CoreError;
    use fedimint_ln_client::contracts::incoming::OfferId;
    use fedimint_ln_client::contracts::{
        ContractOutcome, DecryptedPreimage, OutgoingContractOutcome,
    };
    use fedimint_ln_client::{LightningModuleTypes, LightningOutputOutcome};
    use fedimint_mint_client::{MintModuleTypes, MintOutputOutcome};
    use fedimint_wallet_client::{WalletModuleTypes, WalletOutputOutcome};

    #[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
    pub enum OutputOutcome {
        Mint(<MintModuleTypes as ModuleCommon>::OutputOutcome),
        Wallet(<WalletModuleTypes as ModuleCommon>::OutputOutcome),
        LN(<LightningModuleTypes as ModuleCommon>::OutputOutcome),
    }

    impl From<fedimint_core::core::DynOutputOutcome> for OutputOutcome {
        fn from(oo: fedimint_core::core::DynOutputOutcome) -> Self {
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
        pub fn try_into_variant<T: TryIntoOutcome>(self) -> Result<T, OutputOutcomeError> {
            T::try_into_outcome(self).map_err(|e| OutputOutcomeError::Core(anyhow::Error::from(e)))
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

    impl TryIntoOutcome for fedimint_ln_client::LightningOutputOutcome {
        fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
            match common_outcome {
                OutputOutcome::Mint(_) => Err(CoreError::MismatchingVariant("ln", "mint")),
                OutputOutcome::Wallet(_) => Err(CoreError::MismatchingVariant("ln", "wallet")),
                OutputOutcome::LN(outcome) => Ok(outcome),
            }
        }
    }

    impl TryIntoOutcome for DecryptedPreimage {
        fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
            if let OutputOutcome::LN(fedimint_ln_client::LightningOutputOutcome::Contract {
                outcome: ContractOutcome::Incoming(decrypted_preimage),
                ..
            }) = common_outcome
            {
                Ok(decrypted_preimage)
            } else {
                Err(CoreError::MismatchingVariant("ln::incoming", "other"))
            }
        }
    }

    impl TryIntoOutcome for OfferId {
        fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
            if let OutputOutcome::LN(fedimint_ln_client::LightningOutputOutcome::Offer { id }) =
                common_outcome
            {
                Ok(id)
            } else {
                Err(CoreError::MismatchingVariant("ln::incoming", "other"))
            }
        }
    }

    impl TryIntoOutcome for OutgoingContractOutcome {
        fn try_into_outcome(common_outcome: OutputOutcome) -> Result<Self, CoreError> {
            if let OutputOutcome::LN(fedimint_ln_client::LightningOutputOutcome::Contract {
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
