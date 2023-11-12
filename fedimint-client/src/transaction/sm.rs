//! State machine for submitting transactions

use std::time::Duration;

use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::sleep;
use fedimint_core::transaction::Transaction;
use fedimint_core::TransactionId;
use tracing::warn;

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
                if let Err(submission_error) = submission_result {
                    return Ok(submission_error.to_string());
                }
            }
            Err(error) => {
                if !error.is_retryable() {
                    warn!(target: LOG_TARGET, ?error, "Federation returned non-retryable error");

                    return Err(error.to_string());
                }
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
            Err(error) => {
                if !error.is_retryable() {
                    warn!(target: LOG_TARGET, ?error, "Federation returned non-retryable error");

                    return Err(error.to_string());
                }
            }
        }

        sleep(RETRY_INTERVAL).await;
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
    use std::time::Duration;

    use async_trait::async_trait;
    use fedimint_core::api::{
        DynGlobalApi, DynModuleApi, IFederationApi, IGlobalFederationApi, JsonRpcResult,
    };
    use fedimint_core::config::ClientConfig;
    use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::endpoint_constants::{TRANSACTION_ENDPOINT, WAIT_TRANSACTION_ENDPOINT};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::ApiRequestErased;
    use fedimint_core::task::sleep;
    use fedimint_core::transaction::SerdeTransaction;
    use fedimint_core::util::BoxStream;
    use fedimint_core::{maybe_add_send_sync, OutPoint, PeerId, TransactionId};
    use rand::thread_rng;
    use serde_json::Value;
    use tokio::sync::Mutex;
    use tokio::time::timeout;

    use crate::sm::{ClientSMDatabaseTransaction, Executor, Notifier, OperationState};
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

    impl IGlobalFederationApi for FakeApiClient {}

    #[async_trait]
    impl IFederationApi for FakeApiClient {
        fn all_peers(&self) -> &BTreeSet<PeerId> {
            &self.fake_peers
        }

        fn with_module(&self, _id: ModuleInstanceId) -> DynModuleApi {
            unimplemented!()
        }

        async fn request_raw(
            &self,
            _peer_id: PeerId,
            method: &str,
            params: &[Value],
        ) -> JsonRpcResult<Value> {
            match method {
                TRANSACTION_ENDPOINT => {
                    let api_req: ApiRequestErased =
                        serde_json::from_value(params[0].clone()).unwrap();
                    let serde_tx: SerdeTransaction =
                        serde_json::from_value(api_req.params).unwrap();
                    let tx = serde_tx.try_into_inner(&Default::default()).unwrap();

                    self.txns.lock().await.push(tx.tx_hash());

                    Ok(serde_json::to_value(Ok::<TransactionId, String>(tx.tx_hash())).unwrap())
                }
                WAIT_TRANSACTION_ENDPOINT => {
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

                    Ok(serde_json::to_value(txid).unwrap())
                }
                _ => unimplemented!(),
            }
        }
    }

    struct FakeGlobalContext {
        api: FakeApiClient,
        /// Clone of API wrapped as dyn API (avoids a lot of casting)
        dyn_api: DynGlobalApi,
        executor: Executor<DynGlobalClientContext>,
    }

    impl FakeGlobalContext {
        async fn finalize_and_submit_transaction(
            &self,
            dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
            operation_id: OperationId,
            tx_builder: TransactionBuilder,
        ) -> anyhow::Result<TransactionId> {
            let (transaction, states) = tx_builder.build(secp256k1_zkp::SECP256K1, thread_rng());
            let txid = transaction.tx_hash();

            assert!(states.is_empty(), "A non-empty transaction was submitted");

            let tx_submission_sm = OperationState {
                operation_id,
                state: TxSubmissionStates::Created(transaction),
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
        fn api(&self) -> &DynGlobalApi {
            &self.dyn_api
        }

        fn client_config(&self) -> &ClientConfig {
            unimplemented!()
        }

        fn decoders(&self) -> &ModuleDecoderRegistry {
            unimplemented!()
        }

        fn module_api(&self) -> DynModuleApi {
            unimplemented!()
        }

        async fn claim_input_dyn(
            &self,
            _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
            _input: InstancelessDynClientInput,
        ) -> (TransactionId, Vec<OutPoint>) {
            unimplemented!()
        }

        async fn fund_output_dyn(
            &self,
            _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
            _output: InstancelessDynClientOutput,
        ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)> {
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

        let mut executor_builder = Executor::<DynGlobalClientContext>::builder();
        executor_builder.with_module(TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionContext);
        let executor = executor_builder
            .build(db.clone(), Notifier::new(db.clone()))
            .await;

        let fake_api = FakeApiClient::default();
        let context = Arc::new(FakeGlobalContext {
            api: fake_api.clone(),
            dyn_api: DynGlobalApi::from(fake_api),
            executor: executor.clone(),
        });
        let dyn_context = DynGlobalClientContext::from(context.clone());
        let dyn_context_gen_clone = dyn_context.clone();
        executor
            .start_executor(Arc::new(move |_, _| dyn_context_gen_clone.clone()))
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
