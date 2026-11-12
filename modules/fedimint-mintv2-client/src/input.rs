use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

use fedimint_client::DynGlobalClientContext;
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client_module::error::{AddStateMachinesError, TransactionSubmitError};
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::TransactionId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{
    AutocommitError, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::runtime::sleep;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::{BoxFuture, FmtCompact as _};
use fedimint_mintv2_common::MintInput;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::client_db::RefundAttemptKey;
use crate::{MintClientContext, MintClientStateMachines, SpendableNote};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct InputStateMachine {
    pub common: InputSMCommon,
    pub state: InputSMState,
}

// This layout is persisted in both active and inactive executor records.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Decodable, Encodable)]
pub struct InputSMCommon {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub spendable_notes: Vec<SpendableNote>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum InputSMState {
    Pending,
    Success,
    /// Legacy refund submission. Previously terminal; historical inactive
    /// instances are not automatically reactivated by this change.
    Refunding(OutPointRange),
    // Append variants: the first three discriminants and payloads are persisted.
    RefundingBundle,
    RefundingSingle,
    /// The refund was accepted AND its output notes were stored.
    Refunded,
    /// A singleton refund was rejected. This is not successful recovery, and
    /// resubmitting an unchanged spent/invalid note cannot repair it.
    RefundRejected,
    /// Recovery is delegated to independent singleton state machines. A local
    /// construction failure for one note must not prevent recovering the
    /// others.
    RefundingPerNote,
    /// The refund consumed its inputs, but output issuance failed. Keep the
    /// range for diagnosis; retrying the original inputs would double spend.
    RefundOutputFailed(OutPointRange),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum RefundOutcome {
    Rejected,
    Refunded,
    OutputFailed,
}

impl State for InputStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();
        let context = context.clone();

        match &self.state {
            InputSMState::Pending => vec![StateTransition::new(
                Self::await_pending_transaction(gc, self.common.txid),
                move |_dbtx, result, mut old_state: Self| {
                    Box::pin(async move {
                        old_state.state = if result.is_ok() {
                            InputSMState::Success
                        } else if !old_state.common.spendable_notes.is_empty() {
                            InputSMState::RefundingBundle
                        } else {
                            InputSMState::RefundRejected
                        };
                        old_state
                    })
                },
            )],
            InputSMState::Refunding(range) => vec![StateTransition::new(
                Self::await_refund(context, gc.clone(), self.common.operation_id, *range),
                move |dbtx, result, old_state| {
                    Box::pin(Self::transition_refund(gc.clone(), dbtx, result, old_state))
                },
            )],
            InputSMState::RefundingBundle | InputSMState::RefundingSingle => {
                let common = self.common.clone();
                // Distinguish a singleton child from its parent's bundle attempt.
                let single = matches!(self.state, InputSMState::RefundingSingle);
                let trigger_gc = gc.clone();
                vec![StateTransition::new(
                    async move {
                        let range = Self::submit_refund(&context, &common, single).await;
                        Self::await_refund(context, trigger_gc, common.operation_id, range).await
                    },
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_refund(gc.clone(), dbtx, result, old_state))
                    },
                )]
            }
            InputSMState::Success
            | InputSMState::Refunded
            | InputSMState::RefundRejected
            | InputSMState::RefundingPerNote
            | InputSMState::RefundOutputFailed(_) => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl InputStateMachine {
    async fn await_pending_transaction(
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(txid).await
    }

    async fn submit_refund(
        context: &MintClientContext,
        common: &InputSMCommon,
        single: bool,
    ) -> OutPointRange {
        // A transaction can contain multiple input bundles from this module.
        // Hash the full immutable common state, not just the transaction ID.
        let key = RefundAttemptKey(OperationId::from_encodable(&(common.clone(), single)));
        loop {
            let result = record_refund(context.client_ctx.module_db(), &key, |dbtx| {
                let context = context.clone();
                let common = common.clone();
                Box::pin(async move {
                    let inputs = common
                        .spendable_notes
                        .iter()
                        .map(|note| ClientInput::<MintInput> {
                            input: MintInput::new_v0(note.note()),
                            keys: vec![note.keypair],
                            amounts: Amounts::new_custom(context.amount_unit, note.amount()),
                        })
                        .collect();
                    context
                        .client_ctx
                        .claim_inputs(
                            dbtx,
                            ClientInputBundle::new_no_sm(inputs),
                            common.operation_id,
                        )
                        .await
                })
            })
            .await;
            match result {
                Ok(range) => return range,
                Err(error) => {
                    // claim_inputs can remove funding notes before failing. It
                    // MUST own this rollback boundary, not use the executor's
                    // infallible transition transaction. No submission or
                    // idempotency record survives a failed construction.
                    warn!(
                        operation_id = ?common.operation_id,
                        error = %error.fmt_compact(),
                        "Refund construction failed; retaining notes for retry"
                    );
                    sleep(Duration::from_secs(60)).await;
                }
            }
        }
    }

    async fn await_refund(
        context: MintClientContext,
        global_context: DynGlobalClientContext,
        operation_id: OperationId,
        range: OutPointRange,
    ) -> (OutPointRange, RefundOutcome) {
        let outcome = await_refund_outcome(
            global_context.await_tx_accepted(range.txid()),
            context.client_ctx.await_primary_module_outputs_for_unit(
                operation_id,
                context.amount_unit,
                range.into_iter().collect(),
            ),
        )
        .await;
        (range, outcome)
    }

    fn singleton_refunds(&self) -> Vec<Self> {
        // Duplicate notes in an external bundle must not create duplicate
        // executor states. Each distinct note gets at most one final attempt.
        let mut seen = HashSet::new();
        self.common
            .spendable_notes
            .iter()
            .filter(|note| seen.insert((*note).clone()))
            .map(|note| Self {
                common: InputSMCommon {
                    spendable_notes: vec![note.clone()],
                    ..self.common.clone()
                },
                state: InputSMState::RefundingSingle,
            })
            .collect()
    }

    async fn transition_refund(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        (range, outcome): (OutPointRange, RefundOutcome),
        old_state: InputStateMachine,
    ) -> InputStateMachine {
        let (new_state, children) = old_state.refund_result(range, outcome);
        for child in children {
            match global_context
                .add_state_machine(dbtx, MintClientStateMachines::Input(child))
                .await
            {
                // Overlapping bundles in the same transaction can delegate the
                // same singleton. The existing child already owns its recovery.
                Ok(()) | Err(AddStateMachinesError::StateAlreadyExists) => {}
                Err(error) => panic!("Cannot add singleton refund state machine: {error}"),
            }
        }
        new_state
    }

    fn refund_result(mut self, range: OutPointRange, outcome: RefundOutcome) -> (Self, Vec<Self>) {
        let mut children = vec![];
        self.state = match outcome {
            RefundOutcome::Refunded => InputSMState::Refunded,
            RefundOutcome::OutputFailed => InputSMState::RefundOutputFailed(range),
            RefundOutcome::Rejected
                if self.common.spendable_notes.len() > 1
                    && !matches!(self.state, InputSMState::RefundingSingle) =>
            {
                children = self.singleton_refunds();
                InputSMState::RefundingPerNote
            }
            RefundOutcome::Rejected => InputSMState::RefundRejected,
        };
        (self, children)
    }
}

/// Own the rollback boundary and commit the idempotency record with submission.
/// A canceled/restarted trigger can safely call this again before its executor
/// transition commits.
async fn record_refund<F>(
    database: &Database,
    key: &RefundAttemptKey,
    claim: F,
) -> Result<OutPointRange, AutocommitError<TransactionSubmitError>>
where
    F: for<'a, 'b> Fn(
            &'a mut DatabaseTransaction<'b>,
        ) -> BoxFuture<'a, Result<OutPointRange, TransactionSubmitError>>
        + MaybeSend
        + MaybeSync,
{
    database
        .autocommit(
            |dbtx, _| {
                let claim = &claim;
                Box::pin(async move {
                    if let Some(range) = dbtx.get_value(key).await {
                        return Ok(range);
                    }
                    let range = claim(dbtx).await?;
                    dbtx.insert_new_entry(key, &range).await;
                    Ok(range)
                })
            },
            Some(100),
        )
        .await
}

async fn await_refund_outcome(
    accepted: impl Future<Output = Result<(), String>>,
    outputs: impl Future<Output = Result<(), TransactionSubmitError>>,
) -> RefundOutcome {
    if accepted.await.is_err() {
        RefundOutcome::Rejected
    } else if outputs.await.is_ok() {
        RefundOutcome::Refunded
    } else {
        RefundOutcome::OutputFailed
    }
}

#[cfg(test)]
mod tests;
