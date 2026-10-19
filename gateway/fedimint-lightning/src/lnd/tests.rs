use fedimint_core::encode_bolt11_invoice_features_without_length;
use hex::FromHex;
use lightning::types::features::Bolt11InvoiceFeatures;
use tonic_lnd::lnrpc::invoice::InvoiceState;
use tonic_lnd::lnrpc::{Invoice, InvoiceHtlc, InvoiceHtlcState};

use super::{
    HoldInvoiceAction, PaymentActionKind, channel_amounts_to_lnd, hold_invoice_action,
    hold_invoice_claim_deadline, invoice_preimage_hex, wire_features_to_lnd_feature_vec,
};
use crate::LightningRpcError;

#[test]
fn channel_amount_conversions_preserve_lnd_values() {
    assert_eq!(channel_amounts_to_lnd(0, 0).unwrap(), (0, 0));
    assert_eq!(
        channel_amounts_to_lnd(100_000, 1_000).unwrap(),
        (100_000, 1_000)
    );
    let max = i64::MAX as u64;
    assert_eq!(
        channel_amounts_to_lnd(max, max).unwrap(),
        (i64::MAX, i64::MAX)
    );
}

#[test]
fn channel_amount_conversions_reject_lnd_overflow() {
    for overflow in [i64::MAX as u64 + 1, u64::MAX] {
        for (size, push, field) in [
            (overflow, 0, "channel_size_sats"),
            (1, overflow, "push_amount_sats"),
        ] {
            let err = channel_amounts_to_lnd(size, push).unwrap_err();
            assert!(
                matches!(err, LightningRpcError::FailedToOpenChannel { failure_reason }
                    if failure_reason.contains(field))
            );
        }
    }
}

#[tokio::test]
async fn invalid_channel_amounts_are_rejected_before_connecting_to_lnd() {
    use std::sync::Arc;
    use std::time::Duration;

    use super::GatewayLndClient;
    use crate::{ILnRpcClient, OpenChannelRequest};

    // No usable backend: validation must return without trying to connect.
    let client = GatewayLndClient::new(
        String::new(),
        String::new(),
        String::new(),
        0.0,
        30,
        None,
        Arc::new(|_| Box::pin(async { false })),
    );
    let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        .parse()
        .unwrap();
    let overflow = i64::MAX as u64 + 1;
    for (channel_size_sats, push_amount_sats) in [(overflow, 0), (1, overflow)] {
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            client.open_channel(OpenChannelRequest {
                pubkey,
                host: String::new(),
                channel_size_sats,
                push_amount_sats,
                fee_rate_sats_per_vbyte: None,
                base_fee_msat: None,
                parts_per_million: None,
            }),
        )
        .await
        .expect("invalid channel amounts must not wait for an LND connection");
        assert!(matches!(
            result,
            Err(LightningRpcError::FailedToOpenChannel { .. })
        ));
    }
}

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
