//! State machine for submitting transactions

use std::time::{Duration, SystemTime};

use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::time::now;
use fedimint_core::transaction::Transaction;
use fedimint_core::TransactionId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::sm::{Context, DynContext, OperationId, OperationState, State, StateTransition};
use crate::{DynGlobalClientContext, DynState};

// TODO: how to prevent collisions? Generally reserve some range for custom IDs?
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
        error: TxSubmissionError,
    },
}

#[derive(Debug, Error, Clone, Eq, PartialEq, Serialize, Deserialize, Decodable, Encodable)]
pub enum TxSubmissionError {
    #[error("Tx submission rejected: {0}")]
    SubmitRejected(String),
    #[error("Tx rejected by consensus: {0}")]
    ConsensusRejected(String),
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
                                    Ok(txid) => TxSubmissionStates::Created {
                                        txid,
                                        tx,
                                        next_submission: next_submission + RESUBMISSION_INTERVAL,
                                    },
                                    Err(error) => TxSubmissionStates::Rejected {
                                        txid,
                                        error: TxSubmissionError::SubmitRejected(error),
                                    },
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
                                    Err(error) => TxSubmissionStates::Rejected {
                                        txid,
                                        error: TxSubmissionError::ConsensusRejected(error),
                                    },
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
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

async fn trigger_created_submit(
    tx: Transaction,
    next_submission: SystemTime,
    context: DynGlobalClientContext,
) -> Result<TransactionId, String> {
    fedimint_core::task::sleep(
        next_submission
            .duration_since(now())
            .unwrap_or(Duration::ZERO),
    )
    .await;

    context
        .api()
        .submit_transaction(tx)
        .await
        .map_err(|e| e.to_string())
}

async fn trigger_created_accepted(
    txid: TransactionId,
    context: DynGlobalClientContext,
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

pub fn tx_submission_sm_decoder() -> Decoder {
    let mut decoder_builder = Decoder::builder();
    decoder_builder.with_decodable_type::<OperationState<TxSubmissionStates>>();
    decoder_builder.build()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fmt::{Debug, Formatter};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use async_trait::async_trait;
    use fedimint_core::api::{DynFederationApi, IFederationApi, JsonRpcResult};
    use fedimint_core::config::ClientConfig;
    use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::ApiRequestErased;
    use fedimint_core::task::TaskGroup;
    use fedimint_core::transaction::SerdeTransaction;
    use fedimint_core::util::BoxStream;
    use fedimint_core::{maybe_add_send_sync, PeerId, TransactionId};
    use rand::thread_rng;
    use serde_json::Value;
    use tokio::sync::Mutex;
    use tokio::time::{sleep, timeout};

    use crate::sm::{ClientSMDatabaseTransaction, Executor, Notifier, OperationId, OperationState};
    use crate::transaction::{
        tx_submission_sm_decoder, TransactionBuilder, TxSubmissionContext, TxSubmissionStates,
        TRANSACTION_SUBMISSION_MODULE_INSTANCE,
    };
    use crate::{
        DynGlobalClientContext, IGlobalClientContext, IState, InstancelessDynClientInput,
        InstancelessDynClientOutput,
    };

    #[derive(Debug, Clone)]
    struct FakeApiClient {
        txns: Arc<Mutex<Vec<TransactionId>>>,
        fake_peers: BTreeSet<PeerId>,
    }

    impl Default for FakeApiClient {
        fn default() -> Self {
            FakeApiClient {
                txns: Arc::new(Mutex::new(vec![])),
                fake_peers: vec![PeerId::from(0)].into_iter().collect(),
            }
        }
    }

    #[async_trait]
    impl IFederationApi for FakeApiClient {
        fn all_members(&self) -> &BTreeSet<PeerId> {
            &self.fake_peers
        }

        fn with_module(&self, _id: ModuleInstanceId) -> DynFederationApi {
            unimplemented!()
        }

        async fn request_raw(
            &self,
            _peer_id: PeerId,
            method: &str,
            params: &[Value],
        ) -> JsonRpcResult<Value> {
            match method {
                "transaction" => {
                    let api_req: ApiRequestErased =
                        serde_json::from_value(params[0].clone()).unwrap();
                    let serde_tx: SerdeTransaction =
                        serde_json::from_value(api_req.params).unwrap();
                    let tx = serde_tx.try_into_inner(&Default::default()).unwrap();

                    self.txns.lock().await.push(tx.tx_hash());

                    Ok(serde_json::to_value(tx.tx_hash()).unwrap())
                }
                "wait_transaction" => {
                    let api_req: ApiRequestErased =
                        serde_json::from_value(params[0].clone()).unwrap();
                    let txid: TransactionId = serde_json::from_value(api_req.params).unwrap();

                    loop {
                        let api_lock = self.txns.lock().await;
                        let got_tx = api_lock.contains(&txid);
                        drop(api_lock);
                        if got_tx {
                            break;
                        }
                        sleep(Duration::from_millis(10)).await;
                    }

                    let outcome = fedimint_core::outcome::TransactionStatus::Accepted {
                        epoch: 0,
                        outputs: vec![],
                    };
                    Ok(serde_json::to_value(outcome).unwrap())
                }
                _ => unimplemented!(),
            }
        }
    }

    struct FakeGlobalContext {
        api: FakeApiClient,
        executor: Executor<DynGlobalClientContext>,
    }

    impl FakeGlobalContext {
        async fn finalize_and_submit_transaction(
            &self,
            dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
            operation_id: OperationId,
            tx_builder: TransactionBuilder,
        ) -> anyhow::Result<TransactionId> {
            let (tx, states) = tx_builder.build(secp256k1_zkp::SECP256K1, thread_rng());
            let txid = tx.tx_hash();

            assert!(states.is_empty(), "A non-empty transaction was submitted");

            let tx_submission_sm = OperationState {
                operation_id,
                state: TxSubmissionStates::Created {
                    txid,
                    tx,
                    next_submission: SystemTime::now(),
                },
            }
            .into_dyn(TRANSACTION_SUBMISSION_MODULE_INSTANCE);
            self.executor
                .add_state_machines_dbtx(dbtx.global_tx(), vec![tx_submission_sm])
                .await?;

            Ok(txid)
        }
    }

    impl Debug for FakeGlobalContext {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "FakeGlobalContext({:?})", self.api)
        }
    }

    #[async_trait]
    impl IGlobalClientContext for FakeGlobalContext {
        fn api(&self) -> &(dyn IFederationApi + 'static) {
            &self.api
        }

        fn client_config(&self) -> &ClientConfig {
            unimplemented!()
        }

        fn decoders(&self) -> &ModuleDecoderRegistry {
            unimplemented!()
        }

        fn module_api(&self) -> DynFederationApi {
            unimplemented!()
        }

        async fn claim_input_dyn(
            &self,
            _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
            _input: InstancelessDynClientInput,
        ) -> TransactionId {
            unimplemented!()
        }

        async fn fund_output_dyn(
            &self,
            _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
            _output: InstancelessDynClientOutput,
        ) -> anyhow::Result<TransactionId> {
            unimplemented!()
        }

        async fn add_state_machine_dyn(
            &self,
            _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
            _sm: Box<maybe_add_send_sync!(dyn IState<DynGlobalClientContext>)>,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn transaction_update_stream(
            &self,
            operation_id: OperationId,
        ) -> BoxStream<OperationState<TxSubmissionStates>> {
            self.executor
                .notifier()
                .module_notifier::<OperationState<TxSubmissionStates>>(
                    TRANSACTION_SUBMISSION_MODULE_INSTANCE,
                )
                .subscribe(operation_id)
                .await
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_submission() {
        let db = Database::new(
            MemDatabase::new(),
            ModuleDecoderRegistry::new([(
                TRANSACTION_SUBMISSION_MODULE_INSTANCE,
                ModuleKind::from_static_str("test_transaction_submission"),
                tx_submission_sm_decoder(),
            )]),
        );

        let mut tg = TaskGroup::new();

        let mut executor_builder = Executor::<DynGlobalClientContext>::builder();
        executor_builder.with_module(TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionContext);
        let executor = executor_builder
            .build(db.clone(), Notifier::new(db.clone()))
            .await;

        let context = Arc::new(FakeGlobalContext {
            api: FakeApiClient::default(),
            executor: executor.clone(),
        });
        let dyn_context = DynGlobalClientContext::from(context.clone());
        let dyn_context_gen_clone = dyn_context.clone();
        executor
            .start_executor(&mut tg, Arc::new(move |_, _| dyn_context_gen_clone.clone()))
            .await;

        let operation_id = OperationId([0x42; 32]);

        let tx_builder = TransactionBuilder::new();

        let mut dbtx = db.begin_transaction().await;
        let mut client_tx = ClientSMDatabaseTransaction::new(&mut dbtx, 0);
        let txid = context
            .finalize_and_submit_transaction(&mut client_tx, operation_id, tx_builder)
            .await
            .unwrap();
        dbtx.commit_tx().await;

        timeout(Duration::from_secs(5), async move {
            dyn_context
                .await_tx_accepted(operation_id, txid)
                .await
                .expect("Transaction was not accepted")
        })
        .await
        .unwrap();

        assert_eq!(
            context.api.txns.lock().await.as_slice(),
            &vec![txid],
            "Transaction wasn't submitted as expected"
        );
    }
}
