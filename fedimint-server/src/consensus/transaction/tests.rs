use fedimint_core::Amount;
use fedimint_core::module::{
    AmountUnit, Amounts, CoreConsensusVersion, FeeCharge, FeeComponent, FeePriority,
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
