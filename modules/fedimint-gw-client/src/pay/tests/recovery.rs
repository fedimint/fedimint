mod client_context;
mod lightning;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitcoin::hashes::Hash as _;
use fedimint_api_client::api::{
    DynGlobalApi, DynModuleApi, IModuleFederationApi, IRawFederationApi, ServerError, ServerResult,
};
use fedimint_client::sm::executor::Executor;
use fedimint_client::sm::notifier::Notifier;
use fedimint_client_module::error::TransactionSubmitError;
use fedimint_client_module::module::{ClientContext, ClientContextIface, FinalClientIface};
use fedimint_client_module::sm::ClientSMDatabaseTransaction;
use fedimint_client_module::{
    AddStateMachinesResult, DynGlobalClientContext, IGlobalClientContext,
    InstancelessDynClientInputBundle, InstancelessDynClientOutputBundle,
};
use fedimint_connectors::{ConnectorRegistry, DynGuaridianConnection, PeerStatus};
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{
    Decoder, IntoDynInstance as _, ModuleInstanceId, ModuleKind, OperationId,
};
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiRequestErased, ApiVersion};
use fedimint_core::task::TaskGroup;
use fedimint_core::{OutPointRange, PeerId, TransactionId, apply, async_trait_maybe_send};
use fedimint_eventlog::{EventKind, EventPersistence};
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::ContractAccount;
use fedimint_ln_common::contracts::{FundedContract, IdentifiableContract as _, Preimage};
use fedimint_ln_common::federation_endpoint_constants::{
    ACCOUNT_ENDPOINT, AWAIT_ACCOUNT_ENDPOINT, BLOCK_COUNT_ENDPOINT,
};
use futures::stream::{self, BoxStream};
use tokio::sync::watch;

use self::client_context::MockClientContext;
use self::lightning::MockLightning;
use super::{contract_account, gateway_keypair, payment_data};
use crate::pay::{GatewayPayCommon, GatewayPayInvoice, GatewayPayStateMachine, GatewayPayStates};
use crate::{GatewayClientContext, GatewayClientModule, GatewayClientStateMachines};

const MODULE_ID: ModuleInstanceId = 1;
const PREIMAGE: Preimage = Preimage([42; 32]);

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    fedimint_core::task::timeout(Duration::from_secs(15), future)
        .await
        .expect("recovery test timed out")
}

fn invoice() -> GatewayPayInvoice {
    use bitcoin::hashes::{Hash as _, sha256};
    let hash = sha256::Hash::hash(&PREIMAGE.0);
    GatewayPayInvoice {
        pay_invoice_payload: PayInvoicePayload {
            federation_id: fedimint_core::config::FederationId::dummy(),
            contract_id: contract_account(hash).contract.contract_id(),
            payment_data: payment_data(hash),
            preimage_auth: hash,
        },
    }
}

fn state(state: GatewayPayStates) -> GatewayClientStateMachines {
    GatewayClientStateMachines::Pay(GatewayPayStateMachine {
        common: GatewayPayCommon {
            operation_id: OperationId([1; 32]),
        },
        state,
    })
}

/// Federation availability outlives executor instances, like the remote peers.
#[derive(Debug, Clone)]
struct MockApi {
    peers: BTreeSet<PeerId>,
    online: Arc<AtomicBool>,
    block_online: Arc<AtomicBool>,
    calls: watch::Sender<usize>,
}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for MockApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }
    fn self_peer(&self) -> Option<PeerId> {
        None
    }
    fn with_module(&self, _: ModuleInstanceId) -> DynModuleApi {
        unimplemented!()
    }
    async fn request_raw(
        &self,
        _: PeerId,
        method: &str,
        _: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        if !self.online.load(Ordering::SeqCst)
            || (method == BLOCK_COUNT_ENDPOINT && !self.block_online.load(Ordering::SeqCst))
        {
            // Notify only once the selected outage was actually observed, not
            // when an earlier successful account request happened to start.
            self.calls.send_modify(|calls| *calls += 1);
            return Err(ServerError::Connection("temporary outage".into()));
        }
        match method {
            ACCOUNT_ENDPOINT | AWAIT_ACCOUNT_ENDPOINT => {
                let account =
                    contract_account(invoice().pay_invoice_payload.payment_data.payment_hash());
                Ok(serde_json::to_value(ContractAccount {
                    amount: account.amount,
                    contract: FundedContract::Outgoing(account.contract),
                })
                .unwrap())
            }
            // Deliberately past the dispatch deadline: recovery must use the
            // node's existing payment rather than reject or freshly dispatch.
            BLOCK_COUNT_ENDPOINT => Ok(serde_json::json!(200)),
            _ => panic!("unexpected API method {method}"),
        }
    }
    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(stream::pending())
    }
    async fn wait_for_initialized_connections(&self) {}
    async fn get_peer_connection(&self, _: PeerId) -> ServerResult<DynGuaridianConnection> {
        unimplemented!()
    }
}
impl IModuleFederationApi for MockApi {}

#[derive(Debug)]
struct MockGlobalContext {
    api: DynModuleApi,
    claimed: watch::Sender<bool>,
}

#[apply(async_trait_maybe_send!)]
impl IGlobalClientContext for MockGlobalContext {
    fn module_api(&self) -> DynModuleApi {
        self.api.clone()
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
        _: &mut ClientSMDatabaseTransaction<'_, '_>,
        inputs: InstancelessDynClientInputBundle,
    ) -> Result<OutPointRange, TransactionSubmitError> {
        let [input] = inputs.inputs() else {
            panic!("expected one claim input")
        };
        let input = input
            .input
            .as_any()
            .downcast_ref::<fedimint_ln_common::LightningInput>()
            .unwrap();
        let fedimint_ln_common::LightningInput::V0(input) = input else {
            panic!("expected V0 claim input")
        };
        assert_eq!(input.contract_id, invoice().pay_invoice_payload.contract_id);
        assert_eq!(input.witness, Some(PREIMAGE));
        assert_eq!(input.amount, super::INVOICE_AMOUNT);
        self.claimed.send_replace(true);
        Ok(OutPointRange::new_single(TransactionId::from_byte_array([0; 32]), 0).unwrap())
    }
    async fn fund_output_dyn(
        &self,
        _: &mut ClientSMDatabaseTransaction<'_, '_>,
        _: InstancelessDynClientOutputBundle,
    ) -> Result<OutPointRange, TransactionSubmitError> {
        unimplemented!()
    }
    async fn add_state_machine_dyn(
        &self,
        _: &mut ClientSMDatabaseTransaction<'_, '_>,
        _: Box<dyn fedimint_client_module::sm::IState + Send + Sync>,
    ) -> AddStateMachinesResult {
        unimplemented!()
    }
    async fn log_event_json(
        &self,
        _: &mut ClientSMDatabaseTransaction<'_, '_>,
        _: EventKind,
        _: Option<(ModuleKind, ModuleInstanceId)>,
        _: serde_json::Value,
        _: EventPersistence,
    ) {
        unimplemented!()
    }
    async fn log_event_json_no_dbtx(
        &self,
        _: EventKind,
        _: Option<ModuleKind>,
        _: serde_json::Value,
        _: EventPersistence,
    ) {
        unimplemented!()
    }
    async fn transaction_update_stream(
        &self,
    ) -> BoxStream<'_, fedimint_client_module::transaction::TxSubmissionStatesSM> {
        unimplemented!()
    }
    async fn core_api_version(&self) -> ApiVersion {
        unimplemented!()
    }
}

impl fedimint_core::core::IntoDynInstance for GatewayClientContext {
    type DynType = fedimint_client_module::sm::DynContext;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        Self::DynType::from_typed(instance_id, self)
    }
}

async fn executor(
    db: Database,
    api: Arc<MockApi>,
    lightning: Arc<MockLightning>,
    claimed: watch::Sender<bool>,
) -> (Executor, Arc<MockClientContext>) {
    let final_iface = FinalClientIface::default();
    let client = Arc::new(MockClientContext);
    let erased: Arc<dyn ClientContextIface> = client.clone();
    final_iface.set(Arc::downgrade(&erased));
    let (module_db, token) = db.with_prefix_module_id(MODULE_ID);
    let client_ctx =
        ClientContext::<GatewayClientModule>::new(final_iface.clone(), MODULE_ID, token, module_db);
    let notifier = Notifier::new();
    let mut builder = Executor::builder();
    builder.with_module(
        MODULE_ID,
        GatewayClientContext {
            redeem_key: gateway_keypair(),
            secp: fedimint_core::secp256k1::Secp256k1::new(),
            ln_decoder: Decoder::default(),
            notifier: notifier.module_notifier(MODULE_ID, final_iface),
            client_ctx,
            lightning_manager: lightning,
            connector_registry: ConnectorRegistry::build_from_testing_defaults()
                .bind()
                .await,
        },
    );
    let (wakeup, _) = watch::channel(());
    let executor = builder.build(db, notifier, TaskGroup::new(), wakeup);
    let global = Arc::new(MockGlobalContext {
        api: DynModuleApi::from((*api).clone()),
        claimed,
    });
    executor.start_executor(
        Arc::new(move |_, _| DynGlobalClientContext::from(global.clone())),
        tracing::Span::none(),
    );
    (executor, client)
}

fn test_db() -> Database {
    let mut decoder = Decoder::builder();
    decoder.with_decodable_type::<GatewayClientStateMachines>();
    Database::new(
        MemDatabase::new(),
        ModuleDecoderRegistry::new([(MODULE_ID, fedimint_ln_common::KIND, decoder.build())]),
    )
}

/// Model a crash with the payment in the node's durable store but the original
/// PayInvoice still in the client DB. Rebuild the executor on that same DB.
async fn resume_after_outage(settled: bool, block_outage: bool) {
    let db = test_db();
    let (calls, _) = watch::channel(0);
    let api = Arc::new(MockApi {
        peers: [PeerId::from(0)].into(),
        online: Arc::new(AtomicBool::new(false)),
        block_online: Arc::new(AtomicBool::new(true)),
        calls,
    });
    // Start the old executor offline too: its durable state is explicitly
    // seeded with the pre-crash PayInvoice encoding, while the separate node
    // store already contains the dispatched payment.
    let lightning = Arc::new(MockLightning::new(settled));
    let (claimed, mut claim_rx) = watch::channel(false);
    let mut calls = api.calls.subscribe();
    let (first, first_client) =
        executor(db.clone(), api.clone(), lightning.clone(), claimed.clone()).await;
    let pending = state(GatewayPayStates::PayInvoice(invoice()));
    first
        .add_state_machines(vec![pending.clone().into_dyn(MODULE_ID)])
        .await
        .unwrap();
    bounded(calls.changed()).await.unwrap();
    first.stop_executor();
    drop(first);
    drop(first_client);

    api.online.store(block_outage, Ordering::SeqCst);
    api.block_online.store(!block_outage, Ordering::SeqCst);
    calls.borrow_and_update();
    let (second, _client) = executor(db, api.clone(), lightning.clone(), claimed).await;
    bounded(calls.changed()).await.unwrap();
    bounded(second.await_active_state(pending.into_dyn(MODULE_ID))).await;
    assert!(!*claim_rx.borrow());
    assert_eq!(*lightning.resumes.borrow(), 0);
    api.online.store(true, Ordering::SeqCst);
    api.block_online.store(true, Ordering::SeqCst);
    let mut resumes = lightning.resumes.subscribe();
    bounded(resumes.wait_for(|calls| *calls == 1))
        .await
        .unwrap();
    if !settled {
        assert!(!*claim_rx.borrow());
        lightning.settled.send_replace(true);
    }
    bounded(claim_rx.wait_for(|claimed| *claimed))
        .await
        .unwrap();
    let terminal = state(GatewayPayStates::Preimage(
        vec![fedimint_core::OutPoint {
            txid: TransactionId::from_byte_array([0; 32]),
            out_idx: 0,
        }],
        PREIMAGE,
    ));
    bounded(second.await_inactive_state(terminal.into_dyn(MODULE_ID))).await;
    assert_eq!(
        *lightning.resumes.borrow(),
        1,
        "resume once, never dispatch"
    );
    second.stop_executor();
}

#[tokio::test]
async fn persisted_pay_invoice_recovers_pending_payment_after_account_outage() {
    resume_after_outage(false, false).await;
}

#[tokio::test]
async fn persisted_pay_invoice_recovers_settled_payment_after_account_outage() {
    resume_after_outage(true, false).await;
}

#[tokio::test]
async fn persisted_pay_invoice_recovers_after_block_count_outage() {
    resume_after_outage(true, true).await;
}

#[tokio::test]
async fn fresh_connectivity_failure_never_dispatches() {
    let (calls, _) = watch::channel(0);
    let api = Arc::new(MockApi {
        peers: [PeerId::from(0)].into(),
        online: Arc::new(AtomicBool::new(false)),
        block_online: Arc::new(AtomicBool::new(false)),
        calls,
    });
    let lightning = Arc::new(MockLightning::new(false));
    let (claimed, claim_rx) = watch::channel(false);
    let (executor, _client) = executor(test_db(), api, lightning.clone(), claimed).await;
    executor
        .add_state_machines(vec![
            state(GatewayPayStates::CheckFederation(invoice())).into_dyn(MODULE_ID),
        ])
        .await
        .unwrap();
    bounded(
        executor.await_inactive_state(
            state(GatewayPayStates::FederationUnreachable).into_dyn(MODULE_ID),
        ),
    )
    .await;
    assert_eq!(*lightning.resumes.borrow(), 0);
    assert!(!*claim_rx.borrow());
    executor.stop_executor();
}
