//! State machine for submitting transactions

use std::time::Duration;

use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::transaction::Transaction;
use fedimint_core::TransactionId;

use crate::sm::{Context, DynContext, OperationState, State, StateTransition};
use crate::{DynGlobalClientContext, DynState};

// TODO: how to prevent collisions? Generally reserve some range for custom IDs?
/// Reserved module instance id used for client-internal state machines
pub const TRANSACTION_SUBMISSION_MODULE_INSTANCE: ModuleInstanceId = 0xffff;

pub const LOG_TARGET: &str = "transaction_submission";

const RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct TxSubmissionContext;

impl Context for TxSubmissionContext {}

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
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
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
    /// this should never happen with a honest federation and bug-free code
    NonRetryableError(String),
}

impl State for TxSubmissionStates {
    type ModuleContext = TxSubmissionContext;
    type GlobalContext = DynGlobalClientContext;

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
                        trigger_created_rejected(transaction.clone(), global_context.clone()),
                        move |_dbtx, result, _state| {
                            Box::pin(async move {
                                match result {
                                    Ok(submit_error) => {
                                        TxSubmissionStates::Rejected(txid, submit_error)
                                    }
                                    Err(e) => TxSubmissionStates::NonRetryableError(e),
                                }
                            })
                        },
                    ),
                    StateTransition::new(
                        trigger_created_accepted(txid, global_context.clone()),
                        move |_dbtx, result, _state| {
                            Box::pin(async move {
                                match result {
                                    Ok(()) => TxSubmissionStates::Accepted(txid),
                                    Err(e) => TxSubmissionStates::NonRetryableError(e),
                                }
                            })
                        },
                    ),
                ]
            }
            TxSubmissionStates::Accepted(..) => {
                vec![]
            }
            TxSubmissionStates::Rejected(..) => {
                vec![]
            }
            TxSubmissionStates::NonRetryableError(..) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        unimplemented!("TxSubmissionStates has to be wrapped in OperationState")
    }
}

impl IntoDynInstance for TxSubmissionStates {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

async fn trigger_created_rejected(
    tx: Transaction,
    context: DynGlobalClientContext,
) -> Result<String, String> {
    loop {
        match context.api().submit_transaction(tx.clone()).await {
            Ok(submission_result) => {
                if let Err(submission_error) = submission_result
                    .try_into_inner(context.decoders())
                    .map_err(|error| error.to_string())?
                {
                    return Ok(submission_error.to_string());
                }
            }
            Err(error) => {
                error.report_if_important();
            }
        }

        sleep(RETRY_INTERVAL).await;
    }
}

async fn trigger_created_accepted(
    txid: TransactionId,
    context: DynGlobalClientContext,
) -> Result<(), String> {
    loop {
        match context.api().await_transaction(txid).await {
            Ok(..) => return Ok(()),
            Err(error) => error.report_if_important(),
        }

        sleep(RETRY_INTERVAL).await;
    }
}

pub fn tx_submission_sm_decoder() -> Decoder {
    let mut decoder_builder = Decoder::builder();
    decoder_builder.with_decodable_type::<OperationState<TxSubmissionStates>>();
    decoder_builder.build()
}
