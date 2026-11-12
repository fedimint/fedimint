use bitcoin::hashes::{Hash as _, sha256};

use super::{
    InterceptPaymentRequest, InterceptPaymentResponse, NO_INCOMING_CIRCUIT, PaymentAction, Preimage,
};

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

fn request(incoming_chan_id: u64, htlc_id: u64, expiry: u32) -> InterceptPaymentRequest {
    InterceptPaymentRequest {
        payment_hash: sha256::Hash::all_zeros(),
        amount_msat: 1_000_000,
        incoming_amount_msat: 1_000_000,
        expiry,
        incoming_chan_id,
        short_channel_id: Some(0),
        htlc_id,
    }
}

#[test]
fn held_payment_reports_blocks_to_its_claim_deadline() {
    let (chan_id, htlc_id) = NO_INCOMING_CIRCUIT;
    let held = request(chan_id, htlc_id, 1_000);

    assert_eq!(held.incoming_circuit(), None);
    assert_eq!(held.lnv2_blocks_to_claim_deadline(Some(990)), 10);
    assert_eq!(held.lnv2_blocks_to_claim_deadline(Some(1_001)), 0);
    // Without the current height the deadline counts as reached.
    assert_eq!(held.lnv2_blocks_to_claim_deadline(None), 0);
}

#[test]
fn intercepted_forward_never_leaves_time_to_fund_lnv2() {
    // A forward's expiry is chosen by the sender and LND fails it back before
    // that height, so however far away it looks, an LNv2 contract must not be
    // funded from it.
    let forward = request(101, 0, u32::MAX);

    assert_eq!(forward.incoming_circuit(), Some((101, 0)));
    assert_eq!(forward.lnv2_blocks_to_claim_deadline(Some(990)), 0);
}
