use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::Amount;
use fedimint_core::core::OperationId;
use fedimint_ln_common::contracts::ContractId;

use super::IncomingPaymentStarted;

fn incoming_payment_started(invoice_msats: u64, contract_msats: u64) -> IncomingPaymentStarted {
    IncomingPaymentStarted {
        contract_id: ContractId::all_zeros(),
        payment_hash: sha256::Hash::all_zeros(),
        invoice_amount: Amount::from_msats(invoice_msats),
        contract_amount: Amount::from_msats(contract_msats),
        operation_id: OperationId::new_random(),
    }
}

#[test]
fn incoming_fee_is_htlc_amount_minus_contract_amount() {
    assert_eq!(
        incoming_payment_started(1_000, 990).fee(),
        Some(Amount::from_msats(10))
    );
    assert_eq!(
        incoming_payment_started(1_000, 1_000).fee(),
        Some(Amount::ZERO)
    );
}
