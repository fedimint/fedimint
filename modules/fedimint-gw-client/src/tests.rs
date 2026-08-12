use bitcoin::hashes::{Hash, sha256};
use fedimint_core::Amount;

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
