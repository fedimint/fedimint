use fedimint_core::Amount;
use fedimint_core::module::{
    AmountUnit, Amounts, CoreConsensusVersion, FeeCharge, FeeComponent, FeePriority, FeeRate,
    TransactionItemAmounts, TransactionItemAmountsWithFees, TransactionItemFees,
};

const VERIFIER_OLD: CoreConsensusVersion = CoreConsensusVersion::new(0, 0);
const VERIFIER_NEW: CoreConsensusVersion = CoreConsensusVersion::new(2, 1);

#[test]
fn sanity_test_funding_verifier() {
    for amount_other in [0, 10] {
        let mut v = super::FundingVerifier::default();
        // Add some non-bitcoin amount (balanced) to both sides just to verify
        v.add_input(TransactionItemAmounts {
            amounts: Amounts::new_custom(
                AmountUnit::new_custom(1),
                Amount::from_msats(amount_other),
            ),
            fees: Amounts::ZERO,
        })
        .unwrap()
        .add_output(TransactionItemAmounts {
            amounts: Amounts::new_custom(
                AmountUnit::new_custom(1),
                Amount::from_msats(amount_other),
            ),
            fees: Amounts::ZERO,
        })
        .unwrap();

        v.add_input(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin_msats(3),
            fees: Amounts::new_bitcoin_msats(1),
        })
        .unwrap()
        .add_output(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin_msats(1),
            fees: Amounts::new_bitcoin_msats(1),
        })
        .unwrap();

        assert!(v.clone().verify_funding(VERIFIER_OLD).is_ok());
        assert!(v.clone().verify_funding(VERIFIER_NEW).is_ok());

        v.add_output(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin_msats(1),
            fees: Amounts::ZERO,
        })
        .unwrap();

        assert!(v.clone().verify_funding(VERIFIER_OLD).is_err());
        assert!(v.clone().verify_funding(VERIFIER_NEW).is_err());

        v.add_input(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin_msats(10),
            fees: Amounts::ZERO,
        })
        .unwrap();

        // Old consensus did not allow overpaying
        assert!(v.clone().verify_funding(VERIFIER_OLD).is_err());
        assert!(v.clone().verify_funding(VERIFIER_NEW).is_ok());
    }
}

/// Check if overpaying in a custom currency behaves like before
#[test]
fn sanity_test_funding_verifier_2() {
    let mut v = super::FundingVerifier::default();
    // Add some non-bitcoin amount (balanced) to both sides just to verify
    v.add_input(TransactionItemAmounts {
        amounts: Amounts::new_custom(AmountUnit::new_custom(1), Amount::from_msats(5)),
        fees: Amounts::ZERO,
    })
    .unwrap()
    .add_input(TransactionItemAmounts {
        amounts: Amounts::new_bitcoin_msats(3),
        fees: Amounts::new_bitcoin_msats(1),
    })
    .unwrap()
    .add_output(TransactionItemAmounts {
        amounts: Amounts::new_bitcoin_msats(1),
        fees: Amounts::new_bitcoin_msats(1),
    })
    .unwrap();

    assert!(v.clone().verify_funding(VERIFIER_OLD).is_err());
    assert!(v.clone().verify_funding(VERIFIER_NEW).is_ok());
}

#[test]
fn funding_verifier_rejects_output_plus_fee_overflow() {
    let mut v = super::FundingVerifier::default();

    v.add_input(TransactionItemAmounts {
        amounts: Amounts::new_bitcoin(Amount::from_msats(u64::MAX)),
        fees: Amounts::ZERO,
    })
    .unwrap()
    .add_output(TransactionItemAmounts {
        amounts: Amounts::new_bitcoin(Amount::from_msats(u64::MAX)),
        fees: Amounts::new_bitcoin_msats(1),
    })
    .unwrap();

    assert!(v.verify_funding(VERIFIER_NEW).is_err());
}

#[test]
fn funding_verifier_reduces_fee_components_by_max_priority() {
    let mut v = super::FundingVerifier::default();

    v.add_input_with_fees(TransactionItemAmountsWithFees {
        amounts: Amounts::new_bitcoin_msats(10),
        fees: TransactionItemFees {
            dynamic: vec![
                FeeComponent {
                    fees: Amounts::new_bitcoin_msats(1),
                    charge: FeeCharge::Always,
                },
                FeeComponent {
                    fees: Amounts::new_bitcoin_msats(2),
                    charge: FeeCharge::IfMaxPriority(FeePriority(0)),
                },
            ],
            legacy_floor: Vec::new(),
        },
    })
    .unwrap()
    .add_output_with_fees(TransactionItemAmountsWithFees {
        amounts: Amounts::new_bitcoin_msats(5),
        fees: TransactionItemFees {
            dynamic: vec![FeeComponent {
                fees: Amounts::new_bitcoin_msats(4),
                charge: FeeCharge::IfMaxPriority(FeePriority(1)),
            }],
            legacy_floor: Vec::new(),
        },
    })
    .unwrap();

    let (dynamic_fees, legacy_floor_fees) = v.fee_totals().unwrap();

    assert_eq!(dynamic_fees, Amounts::new_bitcoin_msats(5));
    assert_eq!(legacy_floor_fees, Amounts::ZERO);
}

#[test]
fn funding_verifier_accepts_legacy_floor_during_dynamic_fee_transition() {
    let mut v = super::FundingVerifier::default();

    v.add_input_with_fees(TransactionItemAmountsWithFees {
        amounts: Amounts::new_bitcoin_msats(101),
        fees: TransactionItemFees::ZERO,
    })
    .unwrap()
    .add_output_with_fees(TransactionItemAmountsWithFees {
        amounts: Amounts::new_bitcoin_msats(100),
        fees: TransactionItemFees {
            dynamic: vec![FeeComponent {
                fees: Amounts::new_bitcoin_msats(10),
                charge: FeeCharge::Always,
            }],
            legacy_floor: vec![FeeComponent {
                fees: Amounts::new_bitcoin_msats(1),
                charge: FeeCharge::Always,
            }],
        },
    })
    .unwrap();

    assert!(
        v.verify_funding(CoreConsensusVersion::new(2, 2)).is_ok(),
        "legacy fee floor should be accepted until the tightening consensus version"
    );
}

#[test]
fn dynamic_fee_minimum_uses_a_real_schedule() {
    let priority = FeePriority(1);
    let amount = Amount::from_msats(1_000);
    let fees = TransactionItemFees::from_bitcoin_rate(
        [
            FeeRate::new(Amount::from_msats(10), 10_000).expect("fee rate is below sanity limit"),
            FeeRate::new(Amount::from_msats(1), 100_000).expect("fee rate is below sanity limit"),
        ],
        amount,
        priority,
        Amount::ZERO,
    );

    assert_eq!(
        fees.try_dynamic_fee(priority)
            .expect("fee calculation should not overflow"),
        Amounts::new_bitcoin_msats(20),
        "minimum must be picked from a complete voted schedule"
    );
}

mod core_input {
    use fedimint_core::core::{CoreInput, DynInput, MODULE_INSTANCE_ID_GLOBAL};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IRawDatabaseExt as _};
    use fedimint_core::module::{
        Amounts, CoreConsensusVersion, DYNAMIC_FEES_CORE_CONSENSUS_VERSION,
    };
    use fedimint_core::secp256k1::{Keypair, PublicKey, SecretKey};
    use fedimint_core::{NumPeers, PeerId, secp256k1};

    use crate::consensus::db::process_fee_payout_voucher_vote;
    use crate::consensus::transaction::process_core_input;

    fn test_db() -> Database {
        MemDatabase::new().into_database()
    }

    fn claimant() -> PublicKey {
        Keypair::from_secret_key(
            secp256k1::SECP256K1,
            &SecretKey::from_slice(&[9; 32]).expect("valid secret key"),
        )
        .public_key()
    }

    fn voucher_input(claimant: PublicKey) -> DynInput {
        DynInput::from_typed(
            MODULE_INSTANCE_ID_GLOBAL,
            CoreInput::FeePayoutVoucher { claimant },
        )
    }

    /// Approves a payout of `amounts` to `claimant`, as consensus would.
    async fn approve(db: &Database, claimant: PublicKey, amounts: &Amounts) {
        let mut dbtx = db.begin_transaction().await;

        crate::consensus::db::accrue_fees(&mut dbtx.to_ref_nc(), amounts).await;

        for peer in 0..3u16 {
            process_fee_payout_voucher_vote(
                &mut dbtx.to_ref_nc(),
                NumPeers::from(4),
                claimant,
                amounts,
                PeerId::from(peer),
            )
            .await
            .expect("vote is accepted");
        }

        dbtx.commit_tx().await;
    }

    #[tokio::test]
    async fn approved_voucher_funds_a_transaction_once() {
        let db = test_db();
        let claimant = claimant();
        let amounts = Amounts::new_bitcoin_msats(1000);

        approve(&db, claimant, &amounts).await;

        let mut dbtx = db.begin_transaction().await;

        let meta = process_core_input(
            &mut dbtx.to_ref_nc(),
            &voucher_input(claimant),
            DYNAMIC_FEES_CORE_CONSENSUS_VERSION,
        )
        .await
        .expect("approved voucher is spendable");

        assert_eq!(meta.amount.amounts, amounts);
        assert_eq!(
            meta.pub_key, claimant,
            "the claimant key must be returned so the transaction signature check enforces it"
        );
        assert_eq!(
            meta.amount.fees,
            super::TransactionItemFees::ZERO,
            "a payout must not be charged a fee out of the payout itself"
        );

        assert!(
            process_core_input(
                &mut dbtx.to_ref_nc(),
                &voucher_input(claimant),
                DYNAMIC_FEES_CORE_CONSENSUS_VERSION,
            )
            .await
            .is_err(),
            "a voucher must not fund a second transaction"
        );
    }

    #[tokio::test]
    async fn unapproved_voucher_is_rejected() {
        let db = test_db();
        let mut dbtx = db.begin_transaction().await;

        assert!(
            process_core_input(
                &mut dbtx.to_ref_nc(),
                &voucher_input(claimant()),
                DYNAMIC_FEES_CORE_CONSENSUS_VERSION,
            )
            .await
            .is_err(),
            "a key the guardians never approved must not create value"
        );
    }

    #[tokio::test]
    async fn voucher_is_rejected_before_activation() {
        let db = test_db();
        let claimant = claimant();
        let amounts = Amounts::new_bitcoin_msats(1000);

        approve(&db, claimant, &amounts).await;

        let mut dbtx = db.begin_transaction().await;

        assert!(
            process_core_input(
                &mut dbtx.to_ref_nc(),
                &voucher_input(claimant),
                CoreConsensusVersion::new(2, 1),
            )
            .await
            .is_err(),
            "core inputs must not be spendable before the federation activates them"
        );
    }

    #[tokio::test]
    async fn unknown_core_input_variant_is_rejected() {
        let db = test_db();
        let mut dbtx = db.begin_transaction().await;

        let input = DynInput::from_typed(
            MODULE_INSTANCE_ID_GLOBAL,
            CoreInput::Default {
                variant: 42,
                bytes: vec![1, 2, 3],
            },
        );

        assert!(
            process_core_input(
                &mut dbtx.to_ref_nc(),
                &input,
                DYNAMIC_FEES_CORE_CONSENSUS_VERSION
            )
            .await
            .is_err(),
            "an input variant this version does not know must not create value"
        );
    }
}
