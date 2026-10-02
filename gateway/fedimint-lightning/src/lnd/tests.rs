use fedimint_core::encode_bolt11_invoice_features_without_length;
use hex::FromHex;
use lightning::types::features::Bolt11InvoiceFeatures;
use tonic_lnd::lnrpc::invoice::InvoiceState;
use tonic_lnd::lnrpc::{InvoiceHtlc, InvoiceHtlcState};

use super::{
    HoldInvoiceAction, PaymentActionKind, hold_invoice_action, hold_invoice_claim_deadline,
    wire_features_to_lnd_feature_vec,
};

#[test]
fn hold_invoice_claim_deadline_is_earliest_accepted_expiry_minus_delta() {
    let htlc = |state: InvoiceHtlcState, expiry_height| InvoiceHtlc {
        state: state.into(),
        expiry_height,
        ..Default::default()
    };

    // The gateway assumes LND cancels 36 blocks before the earliest accepted
    // HTLC expires.
    assert_eq!(
        hold_invoice_claim_deadline(&[
            htlc(InvoiceHtlcState::Accepted, 1_000),
            htlc(InvoiceHtlcState::Accepted, 990),
            // A canceled HTLC no longer holds the payment.
            htlc(InvoiceHtlcState::Canceled, 900),
        ]),
        954
    );
    // Nothing accepted, so no deadline to trust.
    assert_eq!(
        hold_invoice_claim_deadline(&[htlc(InvoiceHtlcState::Canceled, 1_000)]),
        0
    );
    assert_eq!(hold_invoice_claim_deadline(&[]), 0);
    // An HTLC expiring within the delta saturates to 0, which refuses funding.
    assert_eq!(
        hold_invoice_claim_deadline(&[htlc(InvoiceHtlcState::Accepted, 10)]),
        0
    );
}

#[test]
fn features_to_lnd() {
    assert_eq!(
        wire_features_to_lnd_feature_vec(&[]).unwrap(),
        Vec::<i32>::new()
    );

    let features_payment_secret = {
        let mut f = Bolt11InvoiceFeatures::empty();
        f.set_payment_secret_optional();
        encode_bolt11_invoice_features_without_length(&f)
    };
    assert_eq!(
        wire_features_to_lnd_feature_vec(&features_payment_secret).unwrap(),
        vec![15]
    );

    // Phoenix feature flags
    let features_payment_secret = Vec::from_hex("20000000000000000000000002000000024100").unwrap();
    assert_eq!(
        wire_features_to_lnd_feature_vec(&features_payment_secret).unwrap(),
        vec![8, 14, 17, 49, 149]
    );
}

#[test]
fn settle_only_succeeds_for_requested_terminal_outcome() {
    assert_eq!(
        hold_invoice_action(PaymentActionKind::Settle, Some(InvoiceState::Accepted)),
        Ok(HoldInvoiceAction::Complete)
    );
    assert_eq!(
        hold_invoice_action(PaymentActionKind::Settle, Some(InvoiceState::Settled)),
        Ok(HoldInvoiceAction::AlreadyComplete)
    );

    for state in [None, Some(InvoiceState::Open), Some(InvoiceState::Canceled)] {
        let error = hold_invoice_action(PaymentActionKind::Settle, state)
            .expect_err("state must not report settlement");
        assert_eq!(error.permanent, state != Some(InvoiceState::Open));
    }
}

#[test]
fn cancel_only_succeeds_for_requested_terminal_outcome() {
    for state in [InvoiceState::Open, InvoiceState::Accepted] {
        assert_eq!(
            hold_invoice_action(PaymentActionKind::Cancel, Some(state)),
            Ok(HoldInvoiceAction::Complete)
        );
    }
    assert_eq!(
        hold_invoice_action(PaymentActionKind::Cancel, Some(InvoiceState::Canceled)),
        Ok(HoldInvoiceAction::AlreadyComplete)
    );

    for state in [None, Some(InvoiceState::Settled)] {
        let error = hold_invoice_action(PaymentActionKind::Cancel, state)
            .expect_err("state must not report cancellation");
        assert!(error.permanent);
    }
}
