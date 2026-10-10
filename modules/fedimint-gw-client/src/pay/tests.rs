use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::key::Keypair;
use fedimint_core::Amount;
use fedimint_core::module::serde_json;
use fedimint_core::secp256k1::{self, SecretKey};
use fedimint_lightning::LightningRpcError;
use fedimint_lightning::payment_failure::PaymentFailureDiagnostics;
use fedimint_ln_client::pay::PaymentData;
use fedimint_ln_common::PrunedInvoice;
use fedimint_ln_common::contracts::IdentifiableContract as _;
use fedimint_ln_common::contracts::outgoing::{OutgoingContract, OutgoingContractAccount};
use lightning_invoice::RoutingFees;

use super::{
    GatewayPayInvoice, OutgoingContractError, OutgoingPaymentError, OutgoingPaymentErrorType,
    TIMELOCK_DELTA,
};
use crate::events::OutgoingPaymentFailed;

const CONSENSUS_BLOCK_COUNT: u64 = 1;
const INVOICE_AMOUNT: Amount = Amount::from_msats(1000);

fn gateway_keypair() -> Keypair {
    Keypair::from_secret_key(
        secp256k1::SECP256K1,
        &SecretKey::from_slice(&[1; 32]).expect("Valid secret key"),
    )
}

/// An account that is valid in every respect other than the payment hash,
/// which the caller chooses so a mismatch can be tested in isolation.
fn contract_account(hash: sha256::Hash) -> OutgoingContractAccount {
    // Comfortably beyond `CONSENSUS_BLOCK_COUNT + TIMELOCK_DELTA`
    contract_account_with_timelock(hash, 100)
}

fn contract_account_with_timelock(hash: sha256::Hash, timelock: u32) -> OutgoingContractAccount {
    contract_account_with(hash, INVOICE_AMOUNT, timelock)
}

fn contract_account_with(
    hash: sha256::Hash,
    amount: Amount,
    timelock: u32,
) -> OutgoingContractAccount {
    let gateway_key = secp256k1::PublicKey::from_keypair(&gateway_keypair());

    OutgoingContractAccount {
        amount,
        contract: OutgoingContract {
            hash,
            gateway_key,
            timelock,
            user_key: gateway_key,
            cancelled: false,
        },
    }
}

fn payment_data(payment_hash: sha256::Hash) -> PaymentData {
    pruned_payment_data(payment_hash, INVOICE_AMOUNT)
}

fn pruned_payment_data(payment_hash: sha256::Hash, amount: Amount) -> PaymentData {
    PaymentData::PrunedInvoice(PrunedInvoice {
        amount,
        destination: secp256k1::PublicKey::from_keypair(&gateway_keypair()),
        destination_features: vec![],
        payment_hash,
        payment_secret: [0; 32],
        route_hints: vec![],
        min_final_cltv_delta: 0,
        expiry_timestamp: u64::MAX,
    })
}

fn validate(
    contract_hash: sha256::Hash,
    invoice_hash: sha256::Hash,
) -> Result<(), OutgoingContractError> {
    validate_account(&contract_account(contract_hash), invoice_hash)
}

/// Surfaces a recorded fresh-dispatch refusal as an error so tests can
/// assert on the drifting gates alongside the hard validation errors.
fn validate_account(
    account: &OutgoingContractAccount,
    invoice_hash: sha256::Hash,
) -> Result<(), OutgoingContractError> {
    validate_payment_data(account, &payment_data(invoice_hash))
}

fn validate_payment_data(
    account: &OutgoingContractAccount,
    payment_data: &PaymentData,
) -> Result<(), OutgoingContractError> {
    GatewayPayInvoice::validate_outgoing_account(
        account,
        gateway_keypair(),
        CONSENSUS_BLOCK_COUNT,
        payment_data,
        RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        },
    )
    .and_then(|parameters| parameters.fresh_dispatch.map(|_| ()))
}

/// Payment data whose invoice expired at the unix epoch.
fn expired_payment_data(payment_hash: sha256::Hash) -> PaymentData {
    match payment_data(payment_hash) {
        PaymentData::PrunedInvoice(mut invoice) => {
            invoice.expiry_timestamp = 0;
            PaymentData::PrunedInvoice(invoice)
        }
        PaymentData::Invoice(..) => unreachable!("the fixture builds a pruned invoice"),
    }
}

/// Guards against the fixture being invalid for some unrelated reason,
/// which would make the rejection test below pass vacuously.
#[test]
fn accepts_contract_matching_the_invoice() {
    let hash = sha256::Hash::hash(b"preimage");

    assert_eq!(validate(hash, hash), Ok(()));
}

/// A timelock close enough to the consensus height that `max_delay`
/// computes to zero must refuse a fresh dispatch: LND treats a CLTV limit
/// of zero as "unset" and substitutes its `--max-cltv-expiry` default,
/// which would let the HTLC outlive the contract timelock and the user
/// refund the contract while the payment is still in flight. The refusal
/// is recorded rather than failing validation so a payment dispatched
/// before a restart can still resume.
#[test]
fn rejects_timelock_yielding_a_max_delay_of_zero() {
    let hash = sha256::Hash::hash(b"preimage");
    let zero_delay_timelock =
        u32::try_from(CONSENSUS_BLOCK_COUNT - 1 + TIMELOCK_DELTA).expect("small constant");

    let validate_with_timelock =
        |timelock| validate_account(&contract_account_with_timelock(hash, timelock), hash);

    // The smallest acceptable timelock, asserted so this test pins the
    // boundary rather than passing against a check that rejects
    // everything.
    assert_eq!(validate_with_timelock(zero_delay_timelock + 1), Ok(()));

    assert_eq!(
        validate_with_timelock(zero_delay_timelock),
        Err(OutgoingContractError::TimeoutTooClose)
    );
    assert_eq!(
        validate_with_timelock(zero_delay_timelock - 1),
        Err(OutgoingContractError::TimeoutTooClose)
    );
}

/// An expired invoice must refuse a fresh dispatch. Like the timelock
/// gate, the refusal is recorded rather than failing validation, so a
/// payment dispatched before a restart can still resume past it.
#[test]
fn records_refusal_for_an_expired_invoice() {
    let hash = sha256::Hash::hash(b"preimage");

    assert_eq!(
        validate_payment_data(&contract_account(hash), &expired_payment_data(hash)),
        Err(OutgoingContractError::InvoiceExpired(0))
    );
}

/// When both drifting gates fail, the timelock refusal is reported: with
/// no timelock budget left the payment cannot be dispatched at all, so
/// expiry never gets a say. Pinned so error reporting stays stable.
#[test]
fn timelock_refusal_takes_precedence_over_expiry() {
    let hash = sha256::Hash::hash(b"preimage");
    let zero_delay_timelock =
        u32::try_from(CONSENSUS_BLOCK_COUNT - 1 + TIMELOCK_DELTA).expect("small constant");

    assert_eq!(
        validate_payment_data(
            &contract_account_with_timelock(hash, zero_delay_timelock),
            &expired_payment_data(hash),
        ),
        Err(OutgoingContractError::TimeoutTooClose)
    );
}

#[test]
fn rejects_contract_not_committing_to_the_invoice() {
    // A client picks the contract id and the invoice independently, so a
    // contract funded against an unrelated hash must not authorize paying
    // this invoice: the preimage we would obtain cannot claim the contract,
    // leaving the gateway out of pocket with no way to recover.
    let contract_hash = sha256::Hash::hash(b"contract preimage");
    let invoice_hash = sha256::Hash::hash(b"unrelated invoice preimage");

    assert_eq!(
        validate(contract_hash, invoice_hash),
        Err(OutgoingContractError::InvalidOutgoingContract {
            contract_id: contract_account(contract_hash).contract.contract_id(),
        })
    );
}

/// A pruned invoice's amount is a raw, caller-supplied `u64`. An amount so
/// large that `payment_amount + fee` overflows must be rejected: otherwise
/// the sum wraps to a small value, the underfunding check passes against a
/// near-empty contract, and the gateway pays out real funds it can never
/// reclaim.
#[test]
fn rejects_invoice_amount_that_would_overflow_the_underfunding_check() {
    let hash = sha256::Hash::hash(b"preimage");

    // A one-millisatoshi base fee makes `u64::MAX + fee` wrap to zero, so
    // before the fix the underfunding check passed against any contract.
    let fees = RoutingFees {
        base_msat: 1,
        proportional_millionths: 0,
    };

    let validate_amount = |contract_amount: Amount, invoice_amount: Amount| {
        GatewayPayInvoice::validate_outgoing_account(
            &contract_account_with(hash, contract_amount, 100),
            gateway_keypair(),
            CONSENSUS_BLOCK_COUNT,
            &pruned_payment_data(hash, invoice_amount),
            fees,
        )
        .map(|_| ())
    };

    // The attack: a wrapping invoice amount against a near-empty contract.
    assert_eq!(
        validate_amount(Amount::from_msats(1), Amount::from_msats(u64::MAX)),
        Err(OutgoingContractError::InvoiceAmountTooLarge)
    );

    // The largest amount whose sum with the fee still fits is accepted when
    // the contract funds it, so the guard rejects exactly the overflow and
    // nothing else.
    let largest_representable = Amount::from_msats(u64::MAX - u64::from(fees.base_msat));
    assert_eq!(
        validate_amount(Amount::from_msats(u64::MAX), largest_representable),
        Ok(())
    );
}

fn lightning_pay_error(
    account: &OutgoingContractAccount,
    lightning_error: LightningRpcError,
) -> OutgoingPaymentError {
    OutgoingPaymentError {
        error_type: OutgoingPaymentErrorType::LightningPayError { lightning_error },
        contract_id: account.contract.contract_id(),
        contract: Some(account.clone()),
    }
}

#[test]
fn lightning_failure_diagnostics_come_from_the_lightning_error() {
    let account = contract_account(sha256::Hash::all_zeros());
    let diagnostics =
        PaymentFailureDiagnostics::new(Some("FAILURE_REASON_NO_ROUTE".to_string()), vec![]);

    let with_diagnostics = lightning_pay_error(
        &account,
        LightningRpcError::FailedPaymentWithDiagnostics {
            failure_reason: "FailureReasonNoRoute".to_string(),
            diagnostics: diagnostics.clone(),
        },
    );
    assert_eq!(
        with_diagnostics.lightning_failure_diagnostics(),
        Some(&diagnostics)
    );

    let without_diagnostics = lightning_pay_error(
        &account,
        LightningRpcError::FailedPayment {
            failure_reason: "FailureReasonNoRoute".to_string(),
        },
    );
    assert_eq!(without_diagnostics.lightning_failure_diagnostics(), None);

    let not_a_lightning_failure = OutgoingPaymentError {
        error_type: OutgoingPaymentErrorType::InvoiceAlreadyPaid,
        ..without_diagnostics
    };
    assert_eq!(
        not_a_lightning_failure.lightning_failure_diagnostics(),
        None
    );
}

/// Failure events logged before diagnostics were recorded must still parse.
#[test]
fn failure_event_without_diagnostics_still_parses() {
    let account = contract_account(sha256::Hash::all_zeros());
    let event = OutgoingPaymentFailed {
        outgoing_contract: account.clone(),
        contract_id: account.contract.contract_id(),
        error: lightning_pay_error(
            &account,
            LightningRpcError::FailedPayment {
                failure_reason: "FailureReasonNoRoute".to_string(),
            },
        ),
        lightning_failure_diagnostics: None,
    };

    let json = serde_json::to_value(&event).expect("Failed to serialize event");
    assert!(json.get("lightning_failure_diagnostics").is_none());

    let parsed: OutgoingPaymentFailed =
        serde_json::from_value(json).expect("Failed to parse event without diagnostics");
    assert_eq!(parsed.lightning_failure_diagnostics, None);
}
