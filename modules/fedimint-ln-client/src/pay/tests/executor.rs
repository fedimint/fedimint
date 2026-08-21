use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fedimint_api_client::api::{
    DynGlobalApi, DynModuleApi, IModuleFederationApi, IRawFederationApi, ServerResult,
};
use fedimint_client::sm::executor::Executor;
use fedimint_client::sm::notifier::Notifier;
use fedimint_client_module::module::{
    ClientContext, ClientContextIface, ClientModule, FinalClientIface, IClientModule,
};
use fedimint_client_module::sm::executor::{ActiveStateKey, IExecutor, InactiveStateKey};
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, DynContext};
use fedimint_client_module::transaction::{FeeQuote, FeeQuoteRequest};
use fedimint_client_module::{
    AddStateMachinesResult, DynGlobalClientContext, IGlobalClientContext,
    InstancelessDynClientInputBundle, InstancelessDynClientOutputBundle, TransactionUpdates,
};
use fedimint_connectors::{DynGuaridianConnection, PeerStatus};
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{
    Decoder, IntoDynInstance as _, ModuleInstanceId, ModuleKind, OperationId,
};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, DatabaseTransaction, NonCommittable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{AmountUnit, ApiRequestErased, ApiVersion};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::TaskGroup;
use fedimint_core::{
    Amount, BitcoinHash as _, OutPoint, OutPointRange, PeerId, TransactionId, apply,
    async_trait_maybe_send,
};
use fedimint_eventlog::{EventKind, EventPersistence};
use fedimint_ln_common::ContractAccount;
use fedimint_ln_common::contracts::{FundedContract, IdentifiableContract as _};
use fedimint_ln_common::federation_endpoint_constants::{
    AWAIT_BLOCK_HEIGHT_ENDPOINT, AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT,
};
use futures::stream::{self, BoxStream};
use tokio::sync::watch;

use super::{
    GatewayPayError, LightningPayFederationUnreachableRefundFailed,
    LightningPayFederationUnreachableRefundSubmitted, LightningPayRefundable,
    LightningPayStateMachine, LightningPayStates, test_common,
};
use crate::{
    LightningClientContext, LightningClientModule, LightningClientStateMachines, LnPayState,
    MockGatewayConnection,
};

const LN_ID: ModuleInstanceId = 1;
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("state-machine test timed out")
}

#[derive(Debug, Clone)]
enum OutputControl {
    Pending,
    Success,
    Failure(String),
}

#[derive(Debug, Clone)]
enum TransactionControl {
    Pending,
    Accepted(TransactionId),
    Rejected(String),
}

struct MockClientContext {
    output: watch::Receiver<OutputControl>,
    output_started: watch::Sender<Option<(OperationId, Vec<OutPoint>)>>,
}

#[apply(async_trait_maybe_send!)]
impl ClientContextIface for MockClientContext {
    fn get_module(&self, _instance: ModuleInstanceId) -> &(dyn IClientModule + Send + Sync) {
        unimplemented!()
    }
    fn api_clone(&self) -> DynGlobalApi {
        unimplemented!()
    }
    fn decoders(&self) -> &ModuleDecoderRegistry {
        unimplemented!()
    }
    async fn finalize_and_submit_transaction(
        &self,
        _operation_id: OperationId,
        _operation_type: &str,
        _operation_meta_gen: Box<dyn Fn(OutPointRange) -> serde_json::Value + Send + Sync>,
        _tx_builder: fedimint_client_module::transaction::TransactionBuilder,
    ) -> anyhow::Result<OutPointRange> {
        unimplemented!()
    }
    async fn finalize_and_submit_transaction_dbtx(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _operation_id: OperationId,
        _operation_type: &str,
        _operation_meta_gen: Box<dyn Fn(OutPointRange) -> serde_json::Value + Send + Sync>,
        _tx_builder: fedimint_client_module::transaction::TransactionBuilder,
    ) -> anyhow::Result<OutPointRange> {
        unimplemented!()
    }
    async fn finalize_and_submit_transaction_inner(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _operation_id: OperationId,
        _tx_builder: fedimint_client_module::transaction::TransactionBuilder,
    ) -> anyhow::Result<OutPointRange> {
        unimplemented!()
    }
    async fn fee_quote(
        &self,
        _operation_id: OperationId,
        _request: FeeQuoteRequest,
    ) -> anyhow::Result<FeeQuote> {
        unimplemented!()
    }
    async fn get_balance_for_unit(&self, _unit: AmountUnit) -> anyhow::Result<Amount> {
        unimplemented!()
    }
    async fn transaction_updates(&self, _operation_id: OperationId) -> TransactionUpdates {
        unimplemented!()
    }
    async fn await_primary_module_outputs(
        &self,
        operation_id: OperationId,
        outputs: Vec<OutPoint>,
    ) -> anyhow::Result<()> {
        self.output_started
            .send_replace(Some((operation_id, outputs)));
        let mut output = self.output.clone();
        loop {
            let control = output.borrow().clone();
            match control {
                OutputControl::Pending => {
                    output.changed().await.expect("output control remains open");
                }
                OutputControl::Success => return Ok(()),
                OutputControl::Failure(error) => return Err(anyhow::anyhow!(error)),
            }
        }
    }
    fn operation_log(&self) -> &dyn fedimint_client_module::oplog::IOperationLog {
        unimplemented!()
    }
    async fn has_active_states(&self, _operation_id: OperationId) -> bool {
        unimplemented!()
    }
    async fn operation_exists(&self, _operation_id: OperationId) -> bool {
        unimplemented!()
    }
    async fn config(&self) -> ClientConfig {
        unimplemented!()
    }
    fn db(&self) -> &Database {
        unimplemented!()
    }
    fn executor(&self) -> &(dyn IExecutor + Send + Sync + 'static) {
        unimplemented!()
    }
    async fn invite_code(&self, _peer: PeerId) -> Option<InviteCode> {
        unimplemented!()
    }
    fn get_internal_payment_markers(&self) -> anyhow::Result<(PublicKey, u64)> {
        unimplemented!()
    }
    async fn log_event_json(
        &self,
        _dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        _module_kind: Option<ModuleKind>,
        _module_id: ModuleInstanceId,
        _kind: EventKind,
        _payload: serde_json::Value,
        _persist: EventPersistence,
    ) {
    }
    async fn read_operation_active_states<'dbtx>(
        &self,
        _operation_id: OperationId,
        _module_id: ModuleInstanceId,
        _dbtx: &'dbtx mut DatabaseTransaction<'_>,
    ) -> Pin<
        Box<
            dyn futures::Stream<
                    Item = (ActiveStateKey, fedimint_client_module::sm::ActiveStateMeta),
                > + Send
                + 'dbtx,
        >,
    > {
        unimplemented!()
    }
    async fn read_operation_inactive_states<'dbtx>(
        &self,
        _operation_id: OperationId,
        _module_id: ModuleInstanceId,
        _dbtx: &'dbtx mut DatabaseTransaction<'_>,
    ) -> Pin<
        Box<
            dyn futures::Stream<
                    Item = (
                        InactiveStateKey,
                        fedimint_client_module::sm::InactiveStateMeta,
                    ),
                > + Send
                + 'dbtx,
        >,
    > {
        unimplemented!()
    }
}

#[derive(Debug)]
struct MockGlobalContext {
    tx: watch::Receiver<TransactionControl>,
    module_api: DynModuleApi,
    refund: OutPointRange,
    expected_contract_id: fedimint_ln_common::contracts::ContractId,
    expected_amount: Amount,
}

#[derive(Debug, Clone)]
enum ReclaimTrigger {
    Never,
    Cancelled(Box<ContractAccount>),
    Timelock,
}

#[derive(Debug)]
struct MockModuleApi {
    peers: BTreeSet<PeerId>,
    trigger: ReclaimTrigger,
}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for MockModuleApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }

    fn self_peer(&self) -> Option<PeerId> {
        None
    }

    fn with_module(&self, _id: ModuleInstanceId) -> DynModuleApi {
        unimplemented!()
    }

    async fn request_raw(
        &self,
        _peer_id: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        match (&self.trigger, method) {
            (ReclaimTrigger::Cancelled(account), AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT) => {
                assert_eq!(
                    serde_json::from_value::<fedimint_ln_common::contracts::ContractId>(
                        params.params.clone()
                    )
                    .expect("contract id parameter"),
                    test_common()
                        .contract
                        .contract_account
                        .contract
                        .contract_id()
                );
                Ok(serde_json::to_value(account).expect("contract serializes"))
            }
            (ReclaimTrigger::Timelock, AWAIT_BLOCK_HEIGHT_ENDPOINT) => {
                assert_eq!(
                    serde_json::from_value::<u64>(params.params.clone())
                        .expect("block-height parameter"),
                    u64::from(test_common().contract.contract_account.contract.timelock)
                );
                Ok(serde_json::Value::Null)
            }
            _ => futures::future::pending().await,
        }
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(stream::pending())
    }

    async fn wait_for_initialized_connections(&self) {}

    async fn get_peer_connection(&self, _peer_id: PeerId) -> ServerResult<DynGuaridianConnection> {
        unimplemented!()
    }
}

impl IModuleFederationApi for MockModuleApi {}

#[apply(async_trait_maybe_send!)]
impl IGlobalClientContext for MockGlobalContext {
    fn module_api(&self) -> DynModuleApi {
        self.module_api.clone()
    }
    async fn client_config(&self) -> ClientConfig {
        unimplemented!()
    }
    fn api(&self) -> &DynGlobalApi {
        unimplemented!()
    }
    fn decoders(&self) -> &ModuleDecoderRegistry {
        unimplemented!()
    }
    async fn claim_inputs_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        inputs: InstancelessDynClientInputBundle,
    ) -> anyhow::Result<OutPointRange> {
        let [input] = inputs.inputs() else {
            panic!("refund must claim exactly one outgoing-contract input")
        };
        let lightning_input = input
            .input
            .as_any()
            .downcast_ref::<fedimint_ln_common::LightningInput>()
            .expect("refund uses a lightning input");
        let fedimint_ln_common::LightningInput::V0(input) = lightning_input else {
            panic!("refund uses the supported lightning input version")
        };
        assert_eq!(input.contract_id, self.expected_contract_id);
        assert_eq!(input.amount, self.expected_amount);
        assert_eq!(input.witness, None);
        Ok(self.refund)
    }
    async fn fund_output_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _outputs: InstancelessDynClientOutputBundle,
    ) -> anyhow::Result<OutPointRange> {
        unimplemented!()
    }
    async fn add_state_machine_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _sm: Box<dyn fedimint_client_module::sm::IState + Send + Sync>,
    ) -> AddStateMachinesResult {
        unimplemented!()
    }
    async fn log_event_json(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _kind: EventKind,
        _module: Option<(ModuleKind, ModuleInstanceId)>,
        _payload: serde_json::Value,
        _persist: EventPersistence,
    ) {
        unimplemented!()
    }
    async fn log_event_json_no_dbtx(
        &self,
        _kind: EventKind,
        _module_kind: Option<ModuleKind>,
        _payload: serde_json::Value,
        _persist: EventPersistence,
    ) {
        unimplemented!()
    }
    async fn transaction_update_stream(
        &self,
    ) -> BoxStream<'_, fedimint_client_module::transaction::TxSubmissionStatesSM> {
        let rx = self.tx.clone();
        Box::pin(stream::unfold(rx, |mut rx| async move {
            loop {
                let update = rx.borrow().clone();
                match update {
                    TransactionControl::Pending => {
                        rx.changed().await.ok()?;
                    }
                    TransactionControl::Accepted(txid) => {
                        let state =
                            fedimint_client_module::transaction::TxSubmissionStates::Accepted(txid);
                        return Some((
                            fedimint_client_module::transaction::TxSubmissionStatesSM {
                                operation_id: OperationId([0; 32]),
                                state,
                            },
                            rx,
                        ));
                    }
                    TransactionControl::Rejected(error) => {
                        let state =
                            fedimint_client_module::transaction::TxSubmissionStates::Rejected(
                                TransactionId::all_zeros(),
                                error,
                            );
                        return Some((
                            fedimint_client_module::transaction::TxSubmissionStatesSM {
                                operation_id: OperationId([0; 32]),
                                state,
                            },
                            rx,
                        ));
                    }
                }
            }
        }))
    }
    async fn core_api_version(&self) -> ApiVersion {
        unimplemented!()
    }
}

impl fedimint_core::core::IntoDynInstance for LightningClientContext {
    type DynType = DynContext;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynContext::from_typed(instance_id, self)
    }
}

fn executor(
    db: Database,
    output: watch::Receiver<OutputControl>,
    tx: watch::Receiver<TransactionControl>,
    trigger: ReclaimTrigger,
) -> (Executor, Arc<MockClientContext>) {
    let final_iface = FinalClientIface::default();
    let (output_started, _) = watch::channel(None);
    let mock_client = Arc::new(MockClientContext {
        output,
        output_started,
    });
    let erased: Arc<dyn ClientContextIface> = mock_client.clone();
    final_iface.set(Arc::downgrade(&erased));
    let (module_db, token) = db.with_prefix_module_id(LN_ID);
    let client_ctx =
        ClientContext::<LightningClientModule>::new(final_iface, LN_ID, token, module_db);
    let mut builder = Executor::builder();
    builder.with_module(
        LN_ID,
        LightningClientContext {
            ln_decoder: Decoder::default(),
            redeem_key: fedimint_core::secp256k1::Keypair::from_secret_key(
                fedimint_core::secp256k1::SECP256K1,
                &fedimint_core::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap(),
            ),
            gateway_conn: Arc::new(MockGatewayConnection),
            client_ctx: Some(client_ctx),
        },
    );
    let (wakeup, _) = watch::channel(());
    let executor = builder.build(db, Notifier::new(), TaskGroup::new(), wakeup);
    let module_api = DynModuleApi::from(MockModuleApi {
        peers: [PeerId::from(0)].into(),
        trigger,
    });
    let common = test_common();
    let global = Arc::new(MockGlobalContext {
        tx,
        module_api,
        refund: OutPointRange::new_single(TransactionId::all_zeros(), 0)
            .expect("one refund output"),
        expected_contract_id: common.contract.contract_account.contract.contract_id(),
        expected_amount: common.contract.contract_account.amount,
    });
    executor.start_executor(
        Arc::new(move |_, _| DynGlobalClientContext::from(global.clone())),
        tracing::Span::none(),
    );
    (executor, mock_client)
}

fn test_db() -> Database {
    let mut decoder = Decoder::builder();
    decoder.with_decodable_type::<LightningClientStateMachines>();
    Database::new(
        MemDatabase::new(),
        ModuleDecoderRegistry::new([(LN_ID, LightningClientModule::kind(), decoder.build())]),
    )
}

fn submitted_state() -> LightningClientStateMachines {
    LightningClientStateMachines::LightningPay(LightningPayStateMachine {
        common: test_common(),
        state: LightningPayStates::FederationUnreachableRefundSubmitted(
            LightningPayFederationUnreachableRefundSubmitted {
                txid: TransactionId::all_zeros(),
                out_points: vec![OutPoint {
                    txid: TransactionId::all_zeros(),
                    out_idx: 7,
                }],
            },
        ),
    })
}

async fn actual_payment_states(executor: &Executor) -> Vec<LightningPayStates> {
    let (active, inactive) = bounded(executor.get_operation_states(OperationId([0; 32]))).await;
    active
        .into_iter()
        .map(|(state, _)| state)
        .chain(inactive.into_iter().map(|(state, _)| state))
        .filter_map(|state| {
            state
                .as_any()
                .downcast_ref::<LightningClientStateMachines>()
                .and_then(|state| match state {
                    LightningClientStateMachines::LightningPay(payment) => {
                        Some(payment.state.clone())
                    }
                    _ => None,
                })
        })
        .collect()
}

fn pending_state() -> LightningClientStateMachines {
    let common = test_common();
    LightningClientStateMachines::LightningPay(LightningPayStateMachine {
        common: common.clone(),
        state: LightningPayStates::FederationUnreachablePendingRefund(LightningPayRefundable {
            contract_id: common.contract.contract_account.contract.contract_id(),
            block_timelock: common.contract.contract_account.contract.timelock,
            error: GatewayPayError::FederationUnreachable,
        }),
    })
}

async fn pending_refund_survives_restart_and_submits(trigger: ReclaimTrigger) {
    let db = test_db();
    let pending = pending_state();
    let (_output_tx, output_rx) = watch::channel(OutputControl::Pending);
    let (_tx_tx, tx_rx) = watch::channel(TransactionControl::Pending);
    let (first, _client) = executor(
        db.clone(),
        output_rx.clone(),
        tx_rx.clone(),
        ReclaimTrigger::Never,
    );
    first
        .add_state_machines(vec![pending.into_dyn(LN_ID)])
        .await
        .unwrap();
    first.stop_executor();

    let (second, _client) = executor(db, output_rx, tx_rx, trigger);
    let submitted = LightningClientStateMachines::LightningPay(LightningPayStateMachine {
        common: test_common(),
        state: LightningPayStates::FederationUnreachableRefundSubmitted(
            LightningPayFederationUnreachableRefundSubmitted {
                txid: TransactionId::all_zeros(),
                out_points: vec![OutPoint {
                    txid: TransactionId::all_zeros(),
                    out_idx: 0,
                }],
            },
        ),
    });
    bounded(second.await_active_state(submitted.into_dyn(LN_ID))).await;
}

#[tokio::test]
async fn pending_refund_survives_restart_and_cancellation() {
    let mut cancelled = test_common().contract.contract_account;
    cancelled.contract.cancelled = true;
    pending_refund_survives_restart_and_submits(ReclaimTrigger::Cancelled(Box::new(
        ContractAccount {
            amount: cancelled.amount,
            contract: FundedContract::Outgoing(cancelled.contract),
        },
    )))
    .await;
}

#[tokio::test]
async fn pending_refund_survives_restart_and_timelock() {
    pending_refund_survives_restart_and_submits(ReclaimTrigger::Timelock).await;
}

#[tokio::test]
async fn submitted_refund_survives_restart_and_waits_for_outputs() {
    let db = test_db();
    let txid = TransactionId::all_zeros();
    let submitted = submitted_state();
    let (output_tx, output_rx) = watch::channel(OutputControl::Pending);
    let (tx_tx, tx_rx) = watch::channel(TransactionControl::Pending);
    let (first, _client) = executor(
        db.clone(),
        output_rx.clone(),
        tx_rx.clone(),
        ReclaimTrigger::Never,
    );
    first
        .add_state_machines(vec![submitted.clone().into_dyn(LN_ID)])
        .await
        .unwrap();
    first.stop_executor();

    let (second, client) = executor(db, output_rx, tx_rx, ReclaimTrigger::Never);
    assert!(second.contains_active_state(LN_ID, submitted.clone()).await);
    let mut output_started = client.output_started.subscribe();
    tx_tx.send_replace(TransactionControl::Accepted(txid));
    let (started_operation, started_outputs) = bounded(async {
        loop {
            if let Some(started) = output_started.borrow().clone() {
                break started;
            }
            output_started
                .changed()
                .await
                .expect("output handshake remains open");
        }
    })
    .await;
    assert_eq!(started_operation, OperationId([0; 32]));
    assert_eq!(started_outputs, vec![OutPoint { txid, out_idx: 7 }]);
    assert!(second.contains_active_state(LN_ID, submitted.clone()).await);
    let actual_waiting = actual_payment_states(&second).await;
    assert!(actual_waiting.iter().any(|state| matches!(
        state,
        LightningPayStates::FederationUnreachableRefundSubmitted(_)
    ) && state.to_public_terminal().is_none()));
    let terminal = LightningClientStateMachines::LightningPay(LightningPayStateMachine {
        common: test_common(),
        state: LightningPayStates::FederationUnreachable(
            super::LightningPayFederationUnreachable {
                txid,
                out_points: vec![OutPoint { txid, out_idx: 7 }],
            },
        ),
    });
    assert!(
        !second
            .contains_inactive_state(LN_ID, terminal.clone())
            .await
    );
    output_tx.send_replace(OutputControl::Success);
    bounded(second.await_inactive_state(terminal.into_dyn(LN_ID))).await;
    let actual_terminal = actual_payment_states(&second).await;
    assert!(
        actual_terminal
            .iter()
            .any(|state| { state.to_public_terminal() == Some(LnPayState::FederationUnreachable) })
    );
}

#[tokio::test]
async fn rejected_refund_rearms_reclaim_after_restart() {
    let db = test_db();
    let submitted = submitted_state();
    let (_output_tx, output_rx) = watch::channel(OutputControl::Pending);
    let (tx_tx, tx_rx) = watch::channel(TransactionControl::Pending);
    let (first, _client) = executor(
        db.clone(),
        output_rx.clone(),
        tx_rx.clone(),
        ReclaimTrigger::Never,
    );
    first
        .add_state_machines(vec![submitted.into_dyn(LN_ID)])
        .await
        .unwrap();
    first.stop_executor();

    let (second, _client) = executor(db, output_rx, tx_rx, ReclaimTrigger::Never);
    tx_tx.send_replace(TransactionControl::Rejected("rejected".to_owned()));
    let common = test_common();
    let pending = LightningClientStateMachines::LightningPay(LightningPayStateMachine {
        common: common.clone(),
        state: LightningPayStates::FederationUnreachablePendingRefund(LightningPayRefundable {
            contract_id: common.contract.contract_account.contract.contract_id(),
            block_timelock: common.contract.contract_account.contract.timelock,
            error: GatewayPayError::FederationUnreachable,
        }),
    });
    bounded(second.await_active_state(pending.into_dyn(LN_ID))).await;
}

#[tokio::test]
async fn definitive_refund_output_failure_is_persisted_for_recovery() {
    const SECRET_SENTINEL: &str = "secret-primary-module-detail";
    let db = test_db();
    let (output_tx, output_rx) = watch::channel(OutputControl::Pending);
    let (tx_tx, tx_rx) = watch::channel(TransactionControl::Pending);
    let (executor, _client) = executor(db, output_rx, tx_rx, ReclaimTrigger::Never);
    executor
        .add_state_machines(vec![submitted_state().into_dyn(LN_ID)])
        .await
        .unwrap();
    tx_tx.send_replace(TransactionControl::Accepted(TransactionId::all_zeros()));
    output_tx.send_replace(OutputControl::Failure(SECRET_SENTINEL.to_owned()));
    let failed = LightningClientStateMachines::LightningPay(LightningPayStateMachine {
        common: test_common(),
        state: LightningPayStates::FederationUnreachableRefundFailed(
            LightningPayFederationUnreachableRefundFailed {
                txid: TransactionId::all_zeros(),
                out_points: vec![OutPoint {
                    txid: TransactionId::all_zeros(),
                    out_idx: 7,
                }],
                error: SECRET_SENTINEL.to_owned(),
            },
        ),
    });
    bounded(executor.await_inactive_state(failed.into_dyn(LN_ID))).await;
    let actual_failed = actual_payment_states(&executor).await;
    let public = actual_failed
        .iter()
        .find_map(LightningPayStates::to_public_terminal)
        .expect("failed refund maps to a public terminal result");
    let LnPayState::UnexpectedError { error_message } = public else {
        panic!("failed refund maps to an unexpected-error result")
    };
    assert!(!error_message.contains(SECRET_SENTINEL));
    assert!(!error_message.contains(&TransactionId::all_zeros().to_string()));
}
