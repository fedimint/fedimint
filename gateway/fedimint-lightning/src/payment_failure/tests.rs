use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;

use super::{FailedHtlcAttempt, MAX_RECORDED_FAILED_ATTEMPTS, PaymentFailureDiagnostics};
use crate::LightningRpcError;

/// An attempt told apart from the others by the channel that failed it.
fn attempt(failing_short_channel_id: u64) -> FailedHtlcAttempt {
    FailedHtlcAttempt {
        route: vec![],
        failure_code: Some("temporary_channel_failure".to_string()),
        failure_source_index: Some(1),
        failing_node: None,
        failing_short_channel_id: Some(failing_short_channel_id),
    }
}

#[test]
fn keeps_every_attempt_up_to_the_cap() {
    let attempts = (0..MAX_RECORDED_FAILED_ATTEMPTS as u64)
        .map(attempt)
        .collect::<Vec<_>>();

    let diagnostics = PaymentFailureDiagnostics::new(None, attempts.clone());

    assert_eq!(diagnostics.failed_attempts, attempts);
    assert_eq!(diagnostics.omitted_failed_attempts, 0);
}

#[test]
fn keeps_only_the_most_recent_attempts_beyond_the_cap() {
    let total = MAX_RECORDED_FAILED_ATTEMPTS as u64 + 3;

    let diagnostics =
        PaymentFailureDiagnostics::new(None, (0..total).map(attempt).collect::<Vec<_>>());

    assert_eq!(diagnostics.omitted_failed_attempts, 3);
    assert_eq!(
        diagnostics.failed_attempts,
        (3..total).map(attempt).collect::<Vec<_>>()
    );
}

fn failed_payment_with_diagnostics() -> LightningRpcError {
    LightningRpcError::FailedPaymentWithDiagnostics {
        failure_reason: "FailureReasonNoRoute".to_string(),
        diagnostics: PaymentFailureDiagnostics::new(
            Some("FAILURE_REASON_NO_ROUTE".to_string()),
            vec![attempt(42)],
        ),
    }
}

/// The diagnostics name nodes and channels on the gateway's routes, so they
/// must never leak into an error message.
#[test]
fn diagnostics_are_kept_out_of_the_error_message() {
    let plain = LightningRpcError::FailedPayment {
        failure_reason: "FailureReasonNoRoute".to_string(),
    };

    assert_eq!(
        failed_payment_with_diagnostics().to_string(),
        plain.to_string()
    );
    assert_eq!(plain.payment_failure_diagnostics(), None);
}

/// `LightningRpcError` is persisted in LNv1 gateway state machines, so the
/// diagnostics must survive a round trip through its encoding.
#[test]
fn diagnostics_survive_consensus_encoding() {
    let error = failed_payment_with_diagnostics();

    let decoded = LightningRpcError::consensus_decode_whole(
        &error.consensus_encode_to_vec(),
        &ModuleDecoderRegistry::default(),
    )
    .expect("Failed to decode an encoded error");

    assert_eq!(decoded, error);
    assert_eq!(
        decoded.payment_failure_diagnostics(),
        error.payment_failure_diagnostics()
    );
}

/// The variant is appended, so errors already persisted by older gateways
/// must decode exactly as before.
#[test]
fn existing_variants_keep_their_encoding() {
    let error = LightningRpcError::FailedPayment {
        failure_reason: "FailureReasonNoRoute".to_string(),
    };
    let encoded = error.consensus_encode_to_vec();

    // `FailedPayment` is the fourth variant.
    assert_eq!(encoded[0], 3);
    assert_eq!(
        LightningRpcError::consensus_decode_whole(&encoded, &ModuleDecoderRegistry::default())
            .expect("Failed to decode an encoded error"),
        error
    );
}
