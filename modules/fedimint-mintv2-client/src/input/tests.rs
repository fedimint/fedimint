use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin_hashes::Hash;
use fedimint_client_module::error::TransactionSubmitError;
use fedimint_core::core::OperationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
use fedimint_core::{IdxRange, OutPointRange, TransactionId};
use fedimint_mintv2_common::Denomination;

use super::{
    InputSMCommon, InputSMState, InputStateMachine, RefundOutcome, await_refund_outcome,
    record_refund,
};
use crate::SpendableNote;
use crate::client_db::{RefundAttemptKey, SpendableNoteKey};

fn note(seed: u8) -> SpendableNote {
    SpendableNote {
        denomination: Denomination(10),
        keypair: Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[seed; 32]).unwrap()),
        signature: tbs::Signature(bls12_381::G1Affine::generator()),
    }
}

fn input(notes: Vec<SpendableNote>) -> InputStateMachine {
    InputStateMachine {
        common: InputSMCommon {
            operation_id: OperationId([1; 32]),
            txid: TransactionId::from_byte_array([2; 32]),
            spendable_notes: notes,
        },
        state: InputSMState::RefundingBundle,
    }
}

fn range() -> OutPointRange {
    OutPointRange::new(
        TransactionId::from_byte_array([3; 32]),
        IdxRange::from(0..1),
    )
}

// Frozen pre-fix layouts: these fixtures cover the payload embedded in both
// active and inactive executor records, including nonempty recovery material.
#[derive(Encodable)]
struct OldInputStateMachine {
    common: OldInputSMCommon,
    state: OldInputSMState,
}

#[derive(Encodable)]
struct OldInputSMCommon {
    operation_id: OperationId,
    txid: TransactionId,
    spendable_notes: Vec<SpendableNote>,
}

#[derive(Encodable)]
enum OldInputSMState {
    Pending,
    Success,
    Refunding(OutPointRange),
}

#[test]
fn previous_input_states_decode_unchanged() {
    for (old_state, state) in [
        (OldInputSMState::Pending, InputSMState::Pending),
        (OldInputSMState::Success, InputSMState::Success),
        (
            OldInputSMState::Refunding(range()),
            InputSMState::Refunding(range()),
        ),
    ] {
        let mut expected = input(vec![note(1), note(2)]);
        expected.state = state;
        let old = OldInputStateMachine {
            common: OldInputSMCommon {
                operation_id: expected.common.operation_id,
                txid: expected.common.txid,
                spendable_notes: expected.common.spendable_notes.clone(),
            },
            state: old_state,
        };
        let bytes = old.consensus_encode_to_vec();
        let decoded =
            InputStateMachine::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.consensus_encode_to_vec(), bytes);
    }
}

#[test]
fn mixed_bundle_recovers_live_notes_without_retrying_spent_notes() {
    let original = input(vec![note(1), note(2)]);
    let (parent, children) = original.refund_result(range(), RefundOutcome::Rejected);
    assert_eq!(parent.state, InputSMState::RefundingPerNote);
    assert_eq!(children.len(), 2);

    // Model the federation rejecting the already-spent singleton and accepting
    // the live singleton. Neither result can construct another refund.
    let (spent, retries) = children[0]
        .clone()
        .refund_result(range(), RefundOutcome::Rejected);
    assert_eq!(spent.state, InputSMState::RefundRejected);
    assert!(retries.is_empty());
    assert_eq!(spent.common.spendable_notes, vec![note(1)]);
    let (live, retries) = children[1]
        .clone()
        .refund_result(range(), RefundOutcome::Refunded);
    assert_eq!(live.state, InputSMState::Refunded);
    assert!(retries.is_empty());
}

#[test]
fn invalid_singleton_is_not_resubmitted() {
    let (state, retries) = input(vec![note(1)]).refund_result(range(), RefundOutcome::Rejected);
    assert_eq!(state.state, InputSMState::RefundRejected);
    assert!(retries.is_empty());
    assert_eq!(state.common.spendable_notes, vec![note(1)]);
}

#[test]
fn duplicate_notes_spawn_one_child_and_refund_attempts_are_bounded() {
    let (parent, children) =
        input(vec![note(1), note(1), note(2)]).refund_result(range(), RefundOutcome::Rejected);
    assert_eq!(parent.state, InputSMState::RefundingPerNote);
    assert_eq!(children.len(), 2);
    for child in children {
        let (_, retries) = child.refund_result(range(), RefundOutcome::Rejected);
        assert!(retries.is_empty());
    }
}

#[tokio::test]
async fn accepted_refund_waits_for_output_storage() {
    let (send, receive) = tokio::sync::oneshot::channel::<()>();
    let outcome = await_refund_outcome(async { Ok(()) }, async {
        receive.await.unwrap();
        Ok(())
    });
    tokio::pin!(outcome);
    assert!(futures::poll!(&mut outcome).is_pending());
    send.send(()).unwrap();
    assert_eq!(outcome.await, RefundOutcome::Refunded);
}

#[tokio::test]
async fn rejected_refund_does_not_wait_for_nonexistent_outputs() {
    assert_eq!(
        await_refund_outcome(async { Err("spent".to_owned()) }, async {
            panic!("Rejected transaction has no outputs")
        },)
        .await,
        RefundOutcome::Rejected
    );
}

#[tokio::test]
async fn failed_issuance_never_retries_consumed_inputs() {
    let outcome = await_refund_outcome(async { Ok(()) }, async {
        Err(TransactionSubmitError::TransactionTooLarge { size: 2, max: 1 })
    })
    .await;
    let (state, retries) = input(vec![note(1), note(2)]).refund_result(range(), outcome);
    assert_eq!(state.state, InputSMState::RefundOutputFailed(range()));
    assert!(retries.is_empty());
}

#[tokio::test]
async fn construction_failure_rolls_back_and_restart_reuses_submission() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let funding_note = SpendableNoteKey(note(1).into());
    let key = RefundAttemptKey(OperationId([42; 32]));
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(&funding_note, &()).await;
    dbtx.commit_tx().await;

    let result = record_refund(&db, &key, |dbtx| {
        let funding_note = funding_note.clone();
        Box::pin(async move {
            // Simulate primary-module funding selection mutating the database
            // before a later transaction finalization failure.
            dbtx.remove_entry(&funding_note).await.unwrap();
            Err(TransactionSubmitError::TransactionTooLarge { size: 2, max: 1 })
        })
    })
    .await;
    assert!(result.is_err());
    let mut dbtx = db.begin_transaction_nc().await;
    assert!(dbtx.get_value(&funding_note).await.is_some());
    assert!(dbtx.get_value(&key).await.is_none());
    drop(dbtx);

    let calls = Arc::new(AtomicUsize::new(0));
    for _ in 0..2 {
        let calls = calls.clone();
        assert_eq!(
            record_refund(&db, &key, |dbtx| {
                let calls = calls.clone();
                let funding_note = funding_note.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    dbtx.remove_entry(&funding_note).await.unwrap();
                    Ok(range())
                })
            })
            .await
            .unwrap(),
            range()
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        db.begin_transaction_nc()
            .await
            .get_value(&funding_note)
            .await
            .is_none()
    );
}
