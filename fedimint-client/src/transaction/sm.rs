//! State machine for submitting transactions

use std::time::Duration;

use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::transaction::{Transaction, TransactionSubmissionOutcome};
use fedimint_core::util::retry;
use fedimint_core::TransactionId;
use fedimint_logging::LOG_CLIENT_NET_API;
use tokio::sync::mpsc;
use tracing::warn;

use crate::sm::{Context, DynContext, State, StateTransition};
use crate::{DynGlobalClientContext, DynState, TxAcceptedEvent, TxRejectedEvent};

// TODO: how to prevent collisions? Generally reserve some range for custom IDs?
/// Reserved module instance id used for client-internal state machines
pub const TRANSACTION_SUBMISSION_MODULE_INSTANCE: ModuleInstanceId = 0xffff;

/// The tx submission and awaiting calls are one of the main api calls and vital
/// for the UX. Ideally we want them to complete fast, though we have noticed in
/// the wild, especially in areas with slow and bad connectivity, that multiple
/// of them can just get stuck fightning and not making progress. For this
/// reason, the max max backoff here is rather long.
fn tx_submission_backoff() -> fedimint_core::util::backoff_util::FibonacciBackoff {
    fedimint_core::util::backoff_util::custom_backoff(
        Duration::from_millis(10),
        if is_running_in_test_env() {
            // In our testing env we often run under very high load, and with tight limits,
            // so we want to force the retries to be relatively fast
            Duration::from_secs(5)
        } else {
            Duration::from_secs(600)
        },
        None,
    )
}

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
        let (tx_submitted_sender, tx_submitted_receiver) = mpsc::channel(1);
        match self.state.clone() {
            TxSubmissionStates::Created(transaction) => {
                let txid = transaction.tx_hash();
                vec![
                    StateTransition::new(
                        TxSubmissionStates::trigger_created_rejected(
                            transaction.clone(),
                            global_context.clone(),
                            tx_submitted_sender,
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
}

impl TxSubmissionStates {
    async fn trigger_created_rejected(
        tx: Transaction,
        context: DynGlobalClientContext,
        tx_submitted: mpsc::Sender<()>,
    ) -> String {
        retry("tx-submit-sm",
             tx_submission_backoff(), || async {
            match context.api().submit_transaction(tx.clone()).await {
                Ok(serde_outcome) => match serde_outcome.try_into_inner(context.decoders()) {
                    Ok(outcome) => {
                        if let TransactionSubmissionOutcome(Err(transaction_error)) = outcome {
                            Ok(transaction_error.to_string())
                        } else {
                            // let the other branch know the tx was successfully submitted
                            let _ = tx_submitted.try_send(());
                            Err(anyhow::anyhow!("Successful submit does not guarantee the tx will be included in the consensus"))?
                        }
                    }
                    Err(decode_error) => {
                        warn!(target: LOG_CLIENT_NET_API, error = %decode_error, "Failed to decode SerdeModuleEncoding");
                        Err(decode_error)?
                    }
                },
                Err(error) => {
                    error.report_if_important();
                    Err(error)?
                }
            }
        }).await.expect("loops forever until cancelled")
    }

    async fn trigger_created_accepted(
        txid: TransactionId,
        context: DynGlobalClientContext,
        mut tx_submitted: mpsc::Receiver<()>,
    ) {
        let _ = tx_submitted.recv().await;
        retry("tx-submit-sm", tx_submission_backoff(), || async {
            // Note: tx is being submitted concurrently via `trigger_created_rejected`
            context
                .api()
                .await_transaction(txid)
                .await
                .inspect_err(|e| {
                    e.report_if_important();
                })?;
            Ok(())
        })
        .await
        .expect("Succeeds or loops forever");
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
