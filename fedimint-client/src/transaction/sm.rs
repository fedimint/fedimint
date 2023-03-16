//! State machine for submitting transactions

use std::time::{Duration, SystemTime};

use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::time::now;
use fedimint_core::transaction::Transaction;
use fedimint_core::TransactionId;
use tracing::warn;

use crate::sm::{Context, DynContext, OperationId, State, StateTransition};
use crate::{DynState, GlobalClientContext};

// TODO: how to preven collisions? Generally reserve some range for custom IDs?
/// Reserved module instance id used for client-internal state machines
pub const TRANSACTION_SUBMISSION_MODULE_INSTANCE: ModuleInstanceId = 0xffff;

pub const LOG_TARGET: &str = "transaction_submission";

/// Every how many seconds an unconfirmed transaction gets re-submitted
const RESUBMISSION_INTERVAL: Duration = Duration::from_secs(5);

/// Every how many seconds the transaction status is checked
const FETCH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct TxSubmissionContext;

impl Context for TxSubmissionContext {}

impl IntoDynInstance for TxSubmissionContext {
    type DynType = DynContext;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynContext::from_typed(instance_id, self)
    }
}

// TODO: refactor states into their own structs that impl `State`. The enum
// merely dispatches fn calls to the right state impl in that scenario
#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine to (re-)submit a transaction till it is either confirmed or
/// rejected by the federation
///
/// ```mermaid
/// flowchart LR
///     Created -- await consensus --> Accepted
///     Created -- await consensus --> Rejected
///     Created -- Periodically submit --> Created
///     Created -- Error on submit --> Rejected
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum TxSubmissionStates {
    /// The transaction has been created and potentially already been submitted,
    /// but no rejection or acceptance happened so far
    Created {
        // TODO: put into wrapper struct
        /// We need this filed to be able to submit multiple transactions in one
        /// operation.
        txid: TransactionId,
        tx: Transaction,
        next_submission: SystemTime,
    },
    /// The transaction has been accepted after consensus was reached on it
    ///
    /// **This state is final**
    Accepted {
        txid: TransactionId,
        // TODO: enable again after awaiting DB prefix writes becomes available
        //epoch: u64
    },
    /// The transaction has been rejected, either by a quorum on submission or
    /// after consensus was reached
    ///
    /// **This state is final**
    Rejected {
        txid: TransactionId,
        // TODO: enable again after awaiting DB prefix writes becomes available
        //error: String
    },
}

impl State for TxSubmissionStates {
    type ModuleContext = TxSubmissionContext;
    type GlobalContext = GlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &GlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            TxSubmissionStates::Created {
                txid,
                tx,
                next_submission,
            } => {
                let txid = *txid;
                vec![
                    StateTransition::new(
                        trigger_created_submit(
                            tx.clone(),
                            *next_submission,
                            global_context.clone(),
                        ),
                        |_dbtx, res, state| {
                            Box::pin(async move {
                                let TxSubmissionStates::Created {
                                    txid,
                                    tx,
                                    next_submission,
                                } = state else {
                                    panic!("Wrong input state for transition fn");
                                };

                                match res {
                                    Ok(()) => TxSubmissionStates::Created {
                                        txid,
                                        tx,
                                        next_submission: next_submission + RESUBMISSION_INTERVAL,
                                    },
                                    Err(_e) => TxSubmissionStates::Rejected { txid },
                                }
                            })
                        },
                    ),
                    StateTransition::new(
                        trigger_created_accepted(tx.tx_hash(), global_context.clone()),
                        move |_dbtx, res, _state| {
                            Box::pin(async move {
                                match res {
                                    Ok(_epoch) => TxSubmissionStates::Accepted { txid },
                                    Err(_error) => TxSubmissionStates::Rejected { txid },
                                }
                            })
                        },
                    ),
                ]
            }
            TxSubmissionStates::Accepted { .. } => {
                vec![]
            }
            TxSubmissionStates::Rejected { .. } => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        unimplemented!("TxSubmissionStates has to be wrapped in OperationState")
    }
}

impl IntoDynInstance for TxSubmissionStates {
    type DynType = DynState<GlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

async fn trigger_created_submit(
    tx: Transaction,
    next_submission: SystemTime,
    context: GlobalClientContext,
) -> Result<(), String> {
    tokio::time::sleep(
        next_submission
            .duration_since(now())
            .unwrap_or(Duration::ZERO),
    )
    .await;

    context
        .api()
        .submit_transaction(tx)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn trigger_created_accepted(
    txid: TransactionId,
    context: GlobalClientContext,
) -> Result<u64, String> {
    // FIXME: use ws subscriptions once they land
    loop {
        match context.api().await_tx_outcome(&txid).await {
            Ok(TransactionStatus::Accepted { epoch, .. }) => break Ok(epoch),
            Ok(TransactionStatus::Rejected(error)) => break Err(error),
            Err(error) => {
                if error.is_retryable() {
                    // FIXME: what to do in this case?
                    warn!(target: LOG_TARGET, ?error, "Federation returned error");
                }
            }
        }
        tokio::time::sleep(FETCH_INTERVAL).await;
    }
}
