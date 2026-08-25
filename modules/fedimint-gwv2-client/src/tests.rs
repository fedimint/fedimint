use std::collections::BTreeSet;

use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::module::serde_json;
use fedimint_lightning::LightningRpcError;

use crate::complete_sm::{CompleteSMCommon, CompletionOutcome, completion_outcome};
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
