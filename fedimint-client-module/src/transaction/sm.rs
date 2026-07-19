//! State machine for submitting transactions

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fedimint_core::TransactionId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::transaction::{Transaction, TransactionSubmissionOutcome};
use fedimint_core::util::backoff_util::custom_backoff;
use fedimint_core::util::retry;
use fedimint_logging::LOG_CLIENT_NET_API;
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::sm::{Context, DynContext, State, StateTransition};
use crate::{DynGlobalClientContext, DynState, TxAcceptedEvent, TxRejectedEvent};

// TODO: how to prevent collisions? Generally reserve some range for custom IDs?
/// Reserved module instance id used for client-internal state machines
pub const TRANSACTION_SUBMISSION_MODULE_INSTANCE: ModuleInstanceId = 0xffff;

/// How long a submission may keep being re-attempted within a single client
/// run, without the transaction being accepted or rejected, before it is
/// reported as stalled.
///
/// Comfortably above the submission backoff's own maximum delay, so a healthy
/// but slow submission does not warn.
const SUBMISSION_STALL_WARN_AFTER: Duration = Duration::from_mins(30);

/// How often to repeat the stall report while the condition persists.
const SUBMISSION_STALL_WARN_INTERVAL: Duration = Duration::from_mins(30);

#[derive(Debug, Clone)]
pub struct TxSubmissionContext;

impl Context for TxSubmissionContext {
    const KIND: Option<ModuleKind> = None;
}

impl IntoDynInstance for TxSubmissionContext {
    type DynType = DynContext;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynContext::from_typed(instance_id, self)
    }
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine to (re-)submit a transaction until it is either accepted or
/// rejected by the federation
///
/// ```mermaid
/// flowchart LR
///     Created -- tx is accepted by consensus --> Accepted
///     Created -- tx is rejected on submission --> Rejected
/// ```
// NOTE: This struct needs to retain the same encoding as [`crate::sm::OperationState`],
// because it was used to replace it, and clients already have it persisted.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct TxSubmissionStatesSM {
    pub operation_id: OperationId,
    pub state: TxSubmissionStates,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum TxSubmissionStates {
    /// The transaction has been created and potentially already been submitted,
    /// but no rejection or acceptance happened so far
    Created(Transaction),
    /// The transaction has been accepted in consensus
    ///
    /// **This state is final**
    Accepted(TransactionId),
    /// The transaction has been rejected by a quorum on submission
    ///
    /// **This state is final**
    Rejected(TransactionId, String),
    // Ideally this would be uncommented:
    // #[deprecated(since = "0.2.2", note = "all errors should be retried")]
    // but due to some rust bug/limitation it seem impossible to prevent
    // existing usages from spamming compilation output with warnings.
    NonRetryableError(String),
}

impl State for TxSubmissionStatesSM {
    type ModuleContext = TxSubmissionContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let operation_id = self.operation_id;
        // There is no point awaiting tx until it was submitted, so
        // `trigger_created_rejected` which does the submitting will use this
        // channel to let the `trigger_created_accepted` which does the awaiting
        // know when it did the submission.
        //
        // Submitting tx does not guarantee that it will get into consensus, so the
        // submitting need to continue.
        let (tx_submitted_sender, tx_submitted_receiver) = watch::channel(false);
        match self.state.clone() {
            TxSubmissionStates::Created(transaction) => {
                let txid = transaction.tx_hash();
                vec![
                    StateTransition::new(
                        TxSubmissionStates::trigger_created_rejected(
                            transaction.clone(),
                            global_context.clone(),
                            tx_submitted_sender,
                            operation_id,
                        ),
                        {
                            let global_context = global_context.clone();
                            move |sm_dbtx, error, _| {
                                let global_context = global_context.clone();
                                Box::pin(async move {
                                    global_context
                                        .log_event(
                                            sm_dbtx,
                                            TxRejectedEvent {
                                                txid,
                                                operation_id,
                                                error: error.clone(),
                                            },
                                        )
                                        .await;
                                    TxSubmissionStatesSM {
                                        state: TxSubmissionStates::Rejected(txid, error),
                                        operation_id,
                                    }
                                })
                            }
                        },
                    ),
                    StateTransition::new(
                        TxSubmissionStates::trigger_created_accepted(
                            txid,
                            global_context.clone(),
                            tx_submitted_receiver,
                        ),
                        {
                            let global_context = global_context.clone();
                            move |sm_dbtx, (), _| {
                                let global_context = global_context.clone();
                                Box::pin(async move {
                                    global_context
                                        .log_event(sm_dbtx, TxAcceptedEvent { txid, operation_id })
                                        .await;
                                    TxSubmissionStatesSM {
                                        state: TxSubmissionStates::Accepted(txid),
                                        operation_id,
                                    }
                                })
                            }
                        },
                    ),
                ]
            }
            TxSubmissionStates::Accepted(..)
            | TxSubmissionStates::Rejected(..)
            | TxSubmissionStates::NonRetryableError(..) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    fn fmt_visualization(&self, f: &mut dyn std::fmt::Write, indent: &str) -> std::fmt::Result {
        match &self.state {
            TxSubmissionStates::Created(tx) => {
                let txid = tx.tx_hash();
                write!(
                    f,
                    "{indent}TxSubmissionStatesSM\n{indent}  state: Created  txid={}  inputs={}  outputs={}",
                    txid.fmt_short(),
                    tx.inputs.len(),
                    tx.outputs.len(),
                )
            }
            TxSubmissionStates::Accepted(txid) => {
                write!(
                    f,
                    "{indent}TxSubmissionStatesSM\n{indent}  state: Accepted  txid={}",
                    txid.fmt_short(),
                )
            }
            TxSubmissionStates::Rejected(txid, err) => {
                write!(
                    f,
                    "{indent}TxSubmissionStatesSM\n{indent}  state: Rejected  txid={}  error={err}",
                    txid.fmt_short(),
                )
            }
            TxSubmissionStates::NonRetryableError(err) => {
                write!(
                    f,
                    "{indent}TxSubmissionStatesSM\n{indent}  state: NonRetryableError  error={err}",
                )
            }
        }
    }
}

impl TxSubmissionStates {
    async fn trigger_created_rejected(
        transaction: Transaction,
        context: DynGlobalClientContext,
        tx_submitted: watch::Sender<bool>,
        operation_id: OperationId,
    ) -> String {
        let txid = transaction.tx_hash();
        debug!(target: LOG_CLIENT_NET_API, %txid, "Submitting transaction");

        let started_s = duration_since_epoch().as_secs();
        let attempts = AtomicU64::new(0);
        // Unix seconds of the last stall report; 0 means "not yet reported".
        let reported_at_s = AtomicU64::new(0);

        retry(
            "tx-submit-sm",
            custom_backoff(Duration::from_secs(2), Duration::from_mins(10), None),
            || async {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                if let TransactionSubmissionOutcome(Err(transaction_error)) = context
                    .api()
                    .submit_transaction(transaction.clone())
                    .await
                    .try_into_inner(context.decoders())?
                {
                    Ok(transaction_error.to_string())
                } else {
                    debug!(
                        target: LOG_CLIENT_NET_API,
                        %txid,
                        "Transaction submission accepted by peer, awaiting consensus",
                    );
                    tx_submitted.send_replace(true);

                    // Re-submitting until the transaction is accepted or rejected is
                    // intentional: submission does not guarantee the transaction reaches
                    // consensus. But a submission stuck in this branch keeps its state
                    // machine alive indefinitely, and at default log levels nothing
                    // reports that it is happening, so surface it.
                    //
                    // Elapsed is measured per client run off a wall clock: a restart
                    // resets it, and a large clock step can skew it. That is acceptable
                    // for a diagnostic, which this is - it changes no behaviour.
                    let now_s = duration_since_epoch().as_secs();
                    let elapsed_s = now_s.saturating_sub(started_s);
                    if SUBMISSION_STALL_WARN_AFTER.as_secs() <= elapsed_s {
                        let last_s = reported_at_s.load(Ordering::Relaxed);
                        if last_s == 0
                            || SUBMISSION_STALL_WARN_INTERVAL.as_secs()
                                <= now_s.saturating_sub(last_s)
                        {
                            reported_at_s.store(now_s, Ordering::Relaxed);
                            warn!(
                                target: LOG_CLIENT_NET_API,
                                %txid,
                                operation_id = %operation_id.fmt_short(),
                                %attempt,
                                %elapsed_s,
                                "Transaction neither accepted nor rejected; still re-submitting",
                            );
                        }
                    }

                    Err(anyhow::anyhow!("Transaction is still valid"))
                }
            },
        )
        .await
        .expect("Number of retries is has no limit")
    }

    async fn trigger_created_accepted(
        txid: TransactionId,
        context: DynGlobalClientContext,
        mut tx_submitted: watch::Receiver<bool>,
    ) {
        let _ = tx_submitted.wait_for(|submitted| *submitted).await;
        context.api().await_transaction(txid).await;
        debug!(target: LOG_CLIENT_NET_API, %txid, "Transaction accepted in consensus");
    }
}

impl IntoDynInstance for TxSubmissionStatesSM {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

pub fn tx_submission_sm_decoder() -> Decoder {
    let mut decoder_builder = Decoder::builder_system();
    decoder_builder.with_decodable_type::<TxSubmissionStatesSM>();
    decoder_builder.build()
}
