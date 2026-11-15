use fedimint_core::Amount;
use fedimint_core::encode_bolt11_invoice_features_without_length;
use fedimint_core::secp256k1::{PublicKey, Secp256k1, SecretKey};
use hex::FromHex;
use lightning::types::features::Bolt11InvoiceFeatures;
use tonic_lnd::lnrpc::failure::FailureCode;
use tonic_lnd::lnrpc::htlc_attempt::HtlcStatus;
use tonic_lnd::lnrpc::invoice::InvoiceState;
use tonic_lnd::lnrpc::{
    Failure, Hop, HtlcAttempt, Invoice, InvoiceHtlc, InvoiceHtlcState, Payment,
    PaymentFailureReason, Route,
};

use super::{
    HoldInvoiceAction, PaymentActionKind, failed_htlc_attempt, failed_payment_error,
    hold_invoice_action, hold_invoice_claim_deadline, invoice_preimage_hex,
    wire_features_to_lnd_feature_vec,
};
use crate::LightningRpcError;

/// An HTLC carrying an MPP record, as every non-keysend HTLC to an LND invoice
/// must.
fn htlc(state: InvoiceHtlcState, expiry_height: i32) -> InvoiceHtlc {
    InvoiceHtlc {
        state: state.into(),
        expiry_height,
        mpp_total_amt_msat: 1_000,
        ..Default::default()
    }
}

/// A keysend HTLC, which carries no MPP record.
fn keysend_htlc(state: InvoiceHtlcState, expiry_height: i32) -> InvoiceHtlc {
    InvoiceHtlc {
        mpp_total_amt_msat: 0,
        ..htlc(state, expiry_height)
    }
}

#[test]
fn hold_invoice_claim_deadline_is_earliest_accepted_expiry_minus_delta() {
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
fn hold_invoice_claim_deadline_distrusts_accepted_keysend_htlcs() {
    assert_eq!(
        hold_invoice_claim_deadline(&[keysend_htlc(InvoiceHtlcState::Accepted, 1_000)]),
        0
    );
    // LND never accepts this mix (an MPP set refuses keysend joins, and a
    // keysend-accepted invoice refuses MPP parts); it is checked anyway.
    assert_eq!(
        hold_invoice_claim_deadline(&[
            htlc(InvoiceHtlcState::Accepted, 1_000),
            keysend_htlc(InvoiceHtlcState::Accepted, 1_000),
        ]),
        0
    );
    // A canceled keysend HTLC no longer holds the payment.
    assert_eq!(
        hold_invoice_claim_deadline(&[
            htlc(InvoiceHtlcState::Accepted, 1_000),
            keysend_htlc(InvoiceHtlcState::Canceled, 1_000),
        ]),
        964
    );
}

/// LND leaves `r_preimage` empty until a HOLD invoice settles. Looking up an
/// in-flight or canceled LNv2 receive used to panic the gateway; it now has no
/// preimage instead.
#[test]
fn invoice_without_preimage_has_none() {
    for state in [
        InvoiceState::Open,
        InvoiceState::Accepted,
        InvoiceState::Canceled,
    ] {
        let invoice = Invoice {
            state: state.into(),
            ..Default::default()
        };
        assert_eq!(invoice_preimage_hex(&invoice), None);
    }
}

#[test]
fn settled_invoice_has_hex_preimage() {
    let invoice = Invoice {
        r_preimage: vec![0xab; 32],
        state: InvoiceState::Settled.into(),
        ..Default::default()
    };
    assert_eq!(invoice_preimage_hex(&invoice), Some("ab".repeat(32)));
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

fn node(seed: u8) -> PublicKey {
    let secret = SecretKey::from_slice(&[seed; 32]).expect("Seed is a valid secret key");
    PublicKey::from_secret_key(&Secp256k1::new(), &secret)
}

/// A three hop route from the gateway: via node 1 over channel 101 and node 2
/// over channel 102 to the destination, node 3, over channel 103.
fn three_hop_route() -> Vec<Hop> {
    (1..=3)
        .map(|i| Hop {
            chan_id: 100 + u64::from(i),
            pub_key: node(i).to_string(),
            amt_to_forward_msat: 1_000,
            fee_msat: if i == 3 { 0 } else { 10 },
            ..Default::default()
        })
        .collect()
}

fn failure(code: FailureCode, failure_source_index: u32) -> Failure {
    Failure {
        code: code.into(),
        failure_source_index,
        ..Default::default()
    }
}

#[test]
fn failed_attempt_records_the_route() {
    let attempt = failed_htlc_attempt(
        &three_hop_route(),
        Some(&failure(FailureCode::TemporaryChannelFailure, 1)),
    );

    assert_eq!(
        attempt
            .route
            .iter()
            .map(|hop| (hop.node_id, hop.short_channel_id))
            .collect::<Vec<_>>(),
        vec![
            (Some(node(1)), 101),
            (Some(node(2)), 102),
            (Some(node(3)), 103),
        ]
    );
    assert_eq!(
        attempt.route[0].amount_to_forward,
        Amount::from_msats(1_000)
    );
    assert_eq!(attempt.route[0].fee, Amount::from_msats(10));
    assert_eq!(
        attempt.failure_code.as_deref(),
        Some("temporary_channel_failure")
    );
}

#[test]
fn intermediate_failure_blames_the_node_and_its_outgoing_channel() {
    // Index 1 is the first hop's node, which failed to forward over the
    // second hop's channel.
    let attempt = failed_htlc_attempt(
        &three_hop_route(),
        Some(&failure(FailureCode::TemporaryChannelFailure, 1)),
    );

    assert_eq!(attempt.failure_source_index, Some(1));
    assert_eq!(attempt.failing_node, Some(node(1)));
    assert_eq!(attempt.failing_short_channel_id, Some(102));
}

#[test]
fn local_failure_blames_the_gateways_first_channel() {
    let attempt = failed_htlc_attempt(
        &three_hop_route(),
        Some(&failure(FailureCode::TemporaryChannelFailure, 0)),
    );

    assert_eq!(attempt.failure_source_index, Some(0));
    assert_eq!(attempt.failing_node, None);
    assert_eq!(attempt.failing_short_channel_id, Some(101));
}

#[test]
fn destination_failure_blames_no_channel() {
    let attempt = failed_htlc_attempt(
        &three_hop_route(),
        Some(&failure(FailureCode::IncorrectOrUnknownPaymentDetails, 3)),
    );

    assert_eq!(
        attempt.failure_code.as_deref(),
        Some("incorrect_or_unknown_payment_details")
    );
    assert_eq!(attempt.failing_node, Some(node(3)));
    assert_eq!(attempt.failing_short_channel_id, None);
}

#[test]
fn unattributable_failures_blame_nobody() {
    // LND reports index 0 for these, which must not blame the gateway.
    for code in [FailureCode::UnreadableFailure, FailureCode::UnknownFailure] {
        let attempt = failed_htlc_attempt(&three_hop_route(), Some(&failure(code, 0)));

        assert_eq!(
            attempt.failure_code.as_deref(),
            Some(code.as_str_name().to_ascii_lowercase().as_str())
        );
        assert_eq!(attempt.failure_source_index, None);
        assert_eq!(attempt.failing_node, None);
        assert_eq!(attempt.failing_short_channel_id, None);
    }
}

#[test]
fn unrecognized_failure_code_is_kept() {
    let attempt = failed_htlc_attempt(
        &three_hop_route(),
        Some(&Failure {
            code: 9_999,
            failure_source_index: 2,
            ..Default::default()
        }),
    );

    assert_eq!(
        attempt.failure_code.as_deref(),
        Some("unrecognized_failure_code_9999")
    );
    assert_eq!(attempt.failing_node, Some(node(2)));
    assert_eq!(attempt.failing_short_channel_id, Some(103));
}

#[test]
fn out_of_range_failure_source_blames_nothing_on_the_route() {
    let attempt = failed_htlc_attempt(
        &three_hop_route(),
        Some(&failure(FailureCode::TemporaryChannelFailure, 7)),
    );

    assert_eq!(attempt.failure_source_index, Some(7));
    assert_eq!(attempt.failing_node, None);
    assert_eq!(attempt.failing_short_channel_id, None);
}

#[test]
fn attempt_without_failure_details_keeps_its_route() {
    let attempt = failed_htlc_attempt(&three_hop_route(), None);

    assert_eq!(attempt.route.len(), 3);
    assert_eq!(attempt.failure_code, None);
    assert_eq!(attempt.failure_source_index, None);
}

fn htlc_attempt(attempt_id: u64, status: HtlcStatus, failing_channel_hop: u32) -> HtlcAttempt {
    HtlcAttempt {
        attempt_id,
        status: status.into(),
        route: Some(Route {
            hops: three_hop_route(),
            ..Default::default()
        }),
        failure: Some(failure(
            FailureCode::TemporaryChannelFailure,
            failing_channel_hop,
        )),
        ..Default::default()
    }
}

#[test]
fn failed_payment_keeps_its_reason_and_failed_attempts_in_order() {
    let payment = Payment {
        status: tonic_lnd::lnrpc::payment::PaymentStatus::Failed.into(),
        failure_reason: PaymentFailureReason::FailureReasonNoRoute.into(),
        htlcs: vec![
            htlc_attempt(2, HtlcStatus::Failed, 1),
            // Only failed attempts say anything about the failure.
            htlc_attempt(3, HtlcStatus::InFlight, 2),
            htlc_attempt(1, HtlcStatus::Failed, 0),
        ],
        ..Default::default()
    };

    let error = failed_payment_error(&payment);

    // The message is unchanged from before diagnostics were recorded.
    assert_eq!(error.to_string(), "Payment failed: FailureReasonNoRoute");
    let LightningRpcError::FailedPaymentWithDiagnostics { diagnostics, .. } = error else {
        panic!("A failed LND payment must carry diagnostics");
    };
    assert_eq!(
        diagnostics.payment_failure_reason.as_deref(),
        Some("FAILURE_REASON_NO_ROUTE")
    );
    assert_eq!(
        diagnostics
            .failed_attempts
            .iter()
            .map(|attempt| attempt.failing_short_channel_id)
            .collect::<Vec<_>>(),
        vec![Some(101), Some(102)]
    );
    assert_eq!(diagnostics.omitted_failed_attempts, 0);
}

#[test]
fn payment_failing_before_any_htlc_has_no_attempts() {
    let payment = Payment {
        status: tonic_lnd::lnrpc::payment::PaymentStatus::Failed.into(),
        failure_reason: PaymentFailureReason::FailureReasonNoRoute.into(),
        ..Default::default()
    };

    let diagnostics = failed_payment_error(&payment)
        .payment_failure_diagnostics()
        .cloned()
        .expect("A failed LND payment must carry diagnostics");

    assert!(diagnostics.failed_attempts.is_empty());
    assert_eq!(
        diagnostics.payment_failure_reason.as_deref(),
        Some("FAILURE_REASON_NO_ROUTE")
    );
}
