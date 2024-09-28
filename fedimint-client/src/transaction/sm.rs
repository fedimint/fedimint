//! State machine for submitting transactions

use std::time::Duration;

use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::runtime::sleep;
use fedimint_core::transaction::{Transaction, TransactionSubmissionOutcome};
use fedimint_core::TransactionId;
use fedimint_logging::LOG_CLIENT_NET_API;
use tracing::warn;

use crate::sm::{Context, DynContext, OperationState, State, StateTransition};
use crate::{DynGlobalClientContext, DynState, TxAcceptedEvent, TxRejectedEvent};

// TODO: how to prevent collisions? Generally reserve some range for custom IDs?
/// Reserved module instance id used for client-internal state machines
pub const TRANSACTION_SUBMISSION_MODULE_INSTANCE: ModuleInstanceId = 0xffff;

pub const LOG_TARGET: &str = "transaction_submission";

const RETRY_INTERVAL: Duration = Duration::from_secs(5);

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

impl State for TxSubmissionStates {
    type ModuleContext = TxSubmissionContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            TxSubmissionStates::Created(transaction) => {
                let txid = transaction.tx_hash();
                vec![
                    StateTransition::new(
                        Self::trigger_created_rejected(transaction.clone(), global_context.clone()),
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
                                                error: error.clone(),
                                            },
                                        )
                                        .await;
                                    TxSubmissionStates::Rejected(txid, error)
                                })
                            }
                        },
                    ),
                    StateTransition::new(
                        Self::trigger_created_accepted(txid, global_context.clone()),
                        {
                            let global_context = global_context.clone();
                            move |sm_dbtx, (), _| {
                                let global_context = global_context.clone();
                                Box::pin(async move {
                                    global_context
                                        .log_event(sm_dbtx, TxAcceptedEvent { txid })
                                        .await;
                                    TxSubmissionStates::Accepted(txid)
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
        unimplemented!("TxSubmissionStates has to be wrapped in OperationState")
    }
}

impl TxSubmissionStates {
    async fn trigger_created_rejected(tx: Transaction, context: DynGlobalClientContext) -> String {
        loop {
            match context.api().submit_transaction(tx.clone()).await {
                Ok(serde_outcome) => match serde_outcome.try_into_inner(context.decoders()) {
                    Ok(outcome) => {
                        if let TransactionSubmissionOutcome(Err(transaction_error)) = outcome {
                            return transaction_error.to_string();
                        }
                    }
                    Err(decode_error) => {
                        warn!(target: LOG_CLIENT_NET_API, error = %decode_error, "Failed to decode SerdeModuleEncoding");
                    }
                },
                Err(error) => {
                    error.report_if_important();
                }
            }

            sleep(RETRY_INTERVAL).await;
        }
    }

    async fn trigger_created_accepted(txid: TransactionId, context: DynGlobalClientContext) {
        loop {
            match context.api().await_transaction(txid).await {
                Ok(..) => return,
                Err(error) => error.report_if_important(),
            }

            sleep(RETRY_INTERVAL).await;
        }
    }
}

impl IntoDynInstance for TxSubmissionStates {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

pub fn tx_submission_sm_decoder() -> Decoder {
    let mut decoder_builder = Decoder::builder_system();
    decoder_builder.with_decodable_type::<OperationState<TxSubmissionStates>>();
    decoder_builder.build()
}
