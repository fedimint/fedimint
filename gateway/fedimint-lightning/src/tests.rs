use bitcoin::hashes::{Hash as _, sha256};

use super::{InterceptPaymentResponse, NO_INCOMING_CIRCUIT, PaymentAction, Preimage};

fn response(incoming_chan_id: u64, htlc_id: u64) -> InterceptPaymentResponse {
    InterceptPaymentResponse {
        incoming_chan_id,
        htlc_id,
        payment_hash: sha256::Hash::all_zeros(),
        action: PaymentAction::Settle(Preimage([0; 32])),
    }
}

#[test]
fn payment_without_incoming_circuit_is_recognized() {
    let (chan_id, htlc_id) = NO_INCOMING_CIRCUIT;
    assert_eq!(response(chan_id, htlc_id).incoming_circuit(), None);
}

#[test]
fn intercepted_forward_keeps_its_circuit() {
    // An intercepted forward must never be mistaken for a payment held by
    // a HOLD invoice, including when it is the first HTLC on its channel
    // and so has htlc id 0.
    assert_eq!(response(101, 0).incoming_circuit(), Some((101, 0)));
    assert_eq!(response(101, 7).incoming_circuit(), Some((101, 7)));
}
