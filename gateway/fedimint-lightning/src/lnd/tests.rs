use fedimint_core::encode_bolt11_invoice_features_without_length;
use hex::FromHex;
use lightning::types::features::Bolt11InvoiceFeatures;
use tonic_lnd::lnrpc::htlc_attempt::HtlcStatus;
use tonic_lnd::lnrpc::invoice::InvoiceState;
use tonic_lnd::lnrpc::{ChannelUpdate, Failure, Hop, HtlcAttempt, Payment, Route};

use super::{
    HoldInvoiceAction, PaymentActionKind, hold_invoice_action, lnd_payment_failure,
    lnd_payment_failure_attempt, wire_features_to_lnd_feature_vec,
};

fn failed_attempt(source: u32, channel_update: Option<ChannelUpdate>) -> HtlcAttempt {
    HtlcAttempt {
        attempt_id: 42,
        status: HtlcStatus::Failed as i32,
        route: Some(Route {
            total_amt_msat: 1234,
            total_fees_msat: 34,
            total_time_lock: 144,
            hops: vec![
                Hop {
                    pub_key: "reporting-node".to_string(),
                    chan_id: 11,
                    amt_to_forward_msat: 1200,
                    fee_msat: 34,
                    expiry: 140,
                    ..Default::default()
                },
                Hop {
                    pub_key: "recipient".to_string(),
                    chan_id: 22,
                    amt_to_forward_msat: 1200,
                    expiry: 130,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }),
        failure: Some(Failure {
            code: tonic_lnd::lnrpc::failure::FailureCode::TemporaryChannelFailure as i32,
            failure_source_index: source,
            channel_update,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn route_failure_does_not_guess_the_failed_channel() {
    let attempt = lnd_payment_failure_attempt(&failed_attempt(1, None)).unwrap();
    assert_eq!(
        attempt.failure_node_pub_key.as_deref(),
        Some("reporting-node")
    );
    // The reporter's incoming channel is 11, but an outgoing-channel failure
    // concerns channel 22. Neither can be identified from the source alone.
    assert_eq!(attempt.failure_channel_id, None);
    assert_eq!(attempt.attempt_id, Some(42));
    assert_eq!(attempt.failure_source_index, Some(1));
    assert_eq!(
        attempt.failure_code.as_deref(),
        Some("TemporaryChannelFailure")
    );
    let route = attempt.route.unwrap();
    assert_eq!(route.total_amount_msat, Some(1234));
    assert_eq!(route.total_fees_msat, Some(34));
    assert_eq!(route.total_time_lock, 144);
    assert_eq!(route.hops[0].channel_id, Some(11));
    assert_eq!(route.hops[1].channel_id, Some(22));
    assert_eq!(route.hops[1].pub_key.as_deref(), Some("recipient"));
}

#[test]
fn route_failure_preserves_explicit_channel_and_handles_unknown_sources() {
    let attempt = lnd_payment_failure_attempt(&failed_attempt(
        1,
        Some(ChannelUpdate {
            chan_id: 99,
            ..Default::default()
        }),
    ))
    .unwrap();
    assert_eq!(attempt.failure_channel_id, Some(99));

    for source in [0, 3, u32::MAX] {
        let attempt = lnd_payment_failure_attempt(&failed_attempt(source, None)).unwrap();
        assert_eq!(attempt.failure_node_pub_key, None);
        assert_eq!(attempt.failure_channel_id, None);
    }
    let mut htlc = failed_attempt(1, None);
    htlc.failure = None;
    htlc.route = None;
    let attempt = lnd_payment_failure_attempt(&htlc).unwrap();
    assert_eq!(attempt.failure_source_index, None);
    assert_eq!(attempt.failure_code, None);
    assert_eq!(attempt.failure_node_pub_key, None);
    assert_eq!(attempt.failure_channel_id, None);
    assert_eq!(attempt.route, None);
}

#[test]
fn payment_diagnostics_include_only_failed_attempts_and_valid_route_values() {
    let mut succeeded = failed_attempt(1, None);
    succeeded.status = HtlcStatus::Succeeded as i32;
    let mut in_flight = succeeded.clone();
    in_flight.status = HtlcStatus::InFlight as i32;
    let mut failed = failed_attempt(2, None);
    let route = failed.route.as_mut().unwrap();
    route.total_amt_msat = -1;
    route.hops[0].pub_key.clear();
    route.hops[0].chan_id = 0;
    route.hops[0].fee_msat = -1;
    let details = lnd_payment_failure(&Payment {
        htlcs: vec![succeeded, failed, in_flight],
        ..Default::default()
    });
    assert_eq!(details.attempts.len(), 1);
    assert_eq!(
        details.attempts[0].failure_node_pub_key.as_deref(),
        Some("recipient")
    );
    let route = details.attempts[0].route.as_ref().unwrap();
    assert_eq!(route.total_amount_msat, None);
    assert_eq!(route.hops[0].pub_key, None);
    assert_eq!(route.hops[0].channel_id, None);
    assert_eq!(route.hops[0].fee_msat, None);
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
