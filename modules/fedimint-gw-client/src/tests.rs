use bitcoin::hashes::{Hash, sha256};
use fedimint_core::Amount;
use fedimint_lightning::InterceptPaymentRequest;

use super::{Htlc, LNV1_HTLC_EXPIRY_SAFETY_MARGIN, UnsafeHtlcExpiry};

fn htlc(incoming_expiry: u32) -> Htlc {
    Htlc {
        payment_hash: sha256::Hash::all_zeros(),
        incoming_amount_msat: Amount::from_msats(1_000),
        outgoing_amount_msat: Amount::from_msats(1_000),
        incoming_expiry,
        short_channel_id: Some(1),
        incoming_chan_id: 2,
        htlc_id: 3,
    }
}

#[test]
fn accepts_htlc_just_above_safe_expiry_boundary() {
    let current_block_height = 1_000;
    let incoming_expiry = current_block_height + LNV1_HTLC_EXPIRY_SAFETY_MARGIN + 1;

    assert_eq!(
        htlc(incoming_expiry).ensure_safe_expiry(current_block_height),
        Ok(())
    );
}

#[test]
fn accepts_htlc_from_pre_upgrade_client_invoice() {
    // Pre-upgrade clients advertise a 30-block route-hint delta on top of an
    // 18-block final delta, so honest payments to their invoices arrive with
    // about 48 blocks remaining. These must keep working while enforcement
    // stays at the legacy margin.
    let current_block_height = 1_000;
    let incoming_expiry = current_block_height + 18 + 30;

    assert_eq!(
        htlc(incoming_expiry).ensure_safe_expiry(current_block_height),
        Ok(())
    );
}

#[test]
fn rejects_htlc_at_safe_expiry_boundary() {
    let current_block_height = 1_000;
    let incoming_expiry = current_block_height + LNV1_HTLC_EXPIRY_SAFETY_MARGIN;

    assert_eq!(
        htlc(incoming_expiry).ensure_safe_expiry(current_block_height),
        Err(UnsafeHtlcExpiry {
            incoming_expiry,
            current_block_height,
            expiry_safety_margin: LNV1_HTLC_EXPIRY_SAFETY_MARGIN,
        })
    );
}

#[test]
fn rejects_expired_htlc_without_underflow() {
    let current_block_height = 1_000;
    let incoming_expiry = 999;

    assert!(
        htlc(incoming_expiry)
            .ensure_safe_expiry(current_block_height)
            .is_err()
    );
}

#[test]
fn accepts_htlc_near_maximum_height_without_overflow() {
    let incoming_expiry = u32::MAX;
    let current_block_height = incoming_expiry - LNV1_HTLC_EXPIRY_SAFETY_MARGIN - 1;

    assert_eq!(
        htlc(incoming_expiry).ensure_safe_expiry(current_block_height),
        Ok(())
    );
}

#[test]
fn htlc_conversion_keeps_incoming_and_outgoing_amounts_distinct() {
    // `amount_msat` is the sender-written onion forward amount, while
    // `incoming_amount_msat` is the value actually locked in the HTLC.
    // Collapsing them into one lets a forged forward amount satisfy the
    // solvency check that guards contract funding, so the conversion must
    // keep the two separate.
    let forged_forward_amount = 1_000_000;
    let real_locked_amount = 1_000;

    let intercept = InterceptPaymentRequest {
        payment_hash: sha256::Hash::all_zeros(),
        amount_msat: forged_forward_amount,
        incoming_amount_msat: real_locked_amount,
        expiry: 500,
        incoming_chan_id: 2,
        short_channel_id: Some(1),
        htlc_id: 3,
    };

    let htlc = Htlc::try_from(intercept).expect("conversion of a valid request succeeds");

    assert_eq!(
        htlc.incoming_amount_msat,
        Amount::from_msats(real_locked_amount),
        "the received amount must come from the real locked value"
    );
    assert_eq!(
        htlc.outgoing_amount_msat,
        Amount::from_msats(forged_forward_amount),
        "the onion forward amount must stay in its own field, never conflated with the received amount"
    );
}
