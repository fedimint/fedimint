use std::collections::BTreeSet;

use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::module::serde_json;
use fedimint_lightning::LightningRpcError;
use fedimint_lightning::payment_failure::PaymentFailureDiagnostics;
use fedimint_lnv2_common::contracts::PaymentImage;

use crate::complete_sm::{CompleteSMCommon, CompletionOutcome, completion_outcome};
use crate::events::OutgoingPaymentFailed;
use crate::send_sm::{Cancelled, SendPaymentError, fresh_dispatch_refusal};
use crate::{
    CompleteSMState, CompleteStateMachine, GatewayClientStateMachinesV2, GatewayOperationMetaV2,
    GatewayOperationRoleV2, IncomingCircuitKey, IncomingRelayPlan, OperationId,
    incoming_circuit_operation_id, incoming_relay_plan, is_legacy_completion_for_circuit,
    legacy_completion_in_states, operation_creation_failed_permanently,
};

fn receive_operation_id() -> OperationId {
    OperationId::from_encodable(&"receive-operation")
}

fn circuit(incoming_chan_id: u64, htlc_id: u64) -> IncomingCircuitKey {
    IncomingCircuitKey {
        incoming_chan_id,
        htlc_id,
    }
}

#[test]
fn relay_tracks_one_receive_and_every_distinct_circuit_in_both_orders() {
    let receive = receive_operation_id();
    let local_hold = incoming_circuit_operation_id(receive, circuit(0, 0));
    let lnv1 = incoming_circuit_operation_id(receive, circuit(42, 7));
    let another_forward = incoming_circuit_operation_id(receive, circuit(42, 8));

    for arrivals in [
        [lnv1, local_hold, another_forward],
        [local_hold, lnv1, another_forward],
    ] {
        let mut receive_exists = false;
        let mut completions = BTreeSet::new();
        for completion in arrivals {
            let plan =
                incoming_relay_plan(receive_exists, completions.contains(&completion), false);
            match plan {
                IncomingRelayPlan::CreateReceiveAndCompletion => receive_exists = true,
                IncomingRelayPlan::AddCompletion => {}
                IncomingRelayPlan::Replay => panic!("distinct circuit was treated as replay"),
            }
            assert!(completions.insert(completion));
        }

        assert!(receive_exists);
        assert_eq!(completions.len(), 3);
        assert_eq!(
            incoming_relay_plan(receive_exists, true, false),
            IncomingRelayPlan::Replay
        );
    }
}

#[test]
fn legacy_active_and_inactive_completions_suppress_same_circuit_replay() {
    let state = GatewayClientStateMachinesV2::Complete(CompleteStateMachine {
        common: CompleteSMCommon {
            operation_id: receive_operation_id(),
            payment_hash: sha256::Hash::all_zeros(),
            incoming_chan_id: 42,
            htlc_id: 7,
        },
        state: CompleteSMState::Completed,
    });

    assert!(is_legacy_completion_for_circuit(&state, circuit(42, 7)));
    assert!(!is_legacy_completion_for_circuit(&state, circuit(42, 8)));
    assert!(!is_legacy_completion_for_circuit(&state, circuit(0, 0)));

    assert!(legacy_completion_in_states(
        std::slice::from_ref(&state),
        &[],
        circuit(42, 7)
    ));
    assert!(legacy_completion_in_states(
        &[],
        std::slice::from_ref(&state),
        circuit(42, 7)
    ));
    assert_eq!(
        incoming_relay_plan(true, false, true),
        IncomingRelayPlan::Replay
    );
}

#[test]
fn operation_creation_race_losers_only_fail_without_a_winner() {
    // Both receive-operation and completion-operation creation use this policy.
    assert!(!operation_creation_failed_permanently(true, true));
    assert!(operation_creation_failed_permanently(true, false));
    assert!(!operation_creation_failed_permanently(false, false));
}

#[test]
fn permanent_completion_failure_is_durable_and_not_logged_as_success() {
    assert_eq!(completion_outcome(Ok(())), CompletionOutcome::Succeeded);

    let outcome = completion_outcome(Err(LightningRpcError::HtlcCompletionRejected {
        failure_reason: "invoice reached opposite terminal state".to_owned(),
    }));
    assert_eq!(
        outcome,
        CompletionOutcome::Failed(
            "HTLC completion cannot reach the requested outcome: invoice reached opposite terminal state"
                .to_owned()
        )
    );
}

#[test]
fn operation_metadata_preserves_legacy_and_dispatches_new_roles() {
    let legacy: GatewayOperationMetaV2 =
        serde_json::from_str("null").expect("legacy metadata must decode");
    assert!(legacy.waits_for_completion());

    assert!(
        GatewayOperationMetaV2::role(GatewayOperationRoleV2::CircuitCompletion)
            .waits_for_completion()
    );
    assert!(!GatewayOperationMetaV2::role(GatewayOperationRoleV2::Receive).waits_for_completion());
    assert!(!GatewayOperationMetaV2::role(GatewayOperationRoleV2::Send).waits_for_completion());
}

#[test]
fn fresh_dispatch_is_refused_once_the_invoice_expires_or_the_budget_runs_out() {
    assert_eq!(fresh_dispatch_refusal(false, 1), None);
    assert_eq!(
        fresh_dispatch_refusal(false, 0),
        Some(Cancelled::TimeoutTooClose),
        "a contract with no blocks left to spare must not be paid out against"
    );
    assert_eq!(
        fresh_dispatch_refusal(true, 1),
        Some(Cancelled::InvoiceExpired)
    );
    assert_eq!(
        fresh_dispatch_refusal(true, 0),
        Some(Cancelled::InvoiceExpired),
        "invoice expiry keeps taking precedence, as before the budget check"
    );
}

fn outgoing_payment_failed(
    lightning_failure_diagnostics: Option<PaymentFailureDiagnostics>,
) -> OutgoingPaymentFailed {
    OutgoingPaymentFailed {
        payment_image: PaymentImage::Hash(sha256::Hash::all_zeros()),
        error: Cancelled::LightningRpcError("Payment failed: FailureReasonNoRoute".to_string()),
        lightning_failure_diagnostics,
    }
}

/// Failure events logged before diagnostics were recorded must still parse,
/// and events without diagnostics keep their previous shape.
#[test]
fn failure_event_without_diagnostics_keeps_its_shape() {
    let json =
        serde_json::to_value(outgoing_payment_failed(None)).expect("Failed to serialize event");
    assert!(json.get("lightning_failure_diagnostics").is_none());

    let parsed: OutgoingPaymentFailed =
        serde_json::from_value(json).expect("Failed to parse event without diagnostics");
    assert_eq!(parsed.lightning_failure_diagnostics, None);
}

#[test]
fn failure_event_records_diagnostics() {
    let diagnostics =
        PaymentFailureDiagnostics::new(Some("FAILURE_REASON_NO_ROUTE".to_string()), vec![]);

    let json = serde_json::to_value(outgoing_payment_failed(Some(diagnostics.clone())))
        .expect("Failed to serialize event");
    let parsed: OutgoingPaymentFailed =
        serde_json::from_value(json).expect("Failed to parse event with diagnostics");

    assert_eq!(parsed.lightning_failure_diagnostics, Some(diagnostics));
}

/// The persisted cancellation keeps exactly the message it had before
/// diagnostics were recorded; the diagnostics only travel alongside it.
#[test]
fn lightning_failure_keeps_its_cancellation_and_carries_diagnostics() {
    let diagnostics =
        PaymentFailureDiagnostics::new(Some("FAILURE_REASON_NO_ROUTE".to_string()), vec![]);

    let error =
        SendPaymentError::from_lightning_error(LightningRpcError::FailedPaymentWithDiagnostics {
            failure_reason: "FailureReasonNoRoute".to_string(),
            diagnostics: diagnostics.clone(),
        });
    assert_eq!(
        error.cancelled,
        Cancelled::LightningRpcError("Payment failed: FailureReasonNoRoute".to_string())
    );
    assert_eq!(error.diagnostics, Some(diagnostics));

    let error = SendPaymentError::from_lightning_error(LightningRpcError::FailedPayment {
        failure_reason: "FailureReasonNoRoute".to_string(),
    });
    assert_eq!(
        error.cancelled,
        Cancelled::LightningRpcError("Payment failed: FailureReasonNoRoute".to_string())
    );
    assert_eq!(error.diagnostics, None);
}
