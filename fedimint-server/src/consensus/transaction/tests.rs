use fedimint_core::Amount;
use fedimint_core::module::{AmountUnit, Amounts, CoreConsensusVersion, TransactionItemAmounts};

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
