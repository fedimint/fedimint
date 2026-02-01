use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Formatter};
use std::future::{Future, pending};
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow, bail, format_err};
use async_stream::try_stream;
use bitcoin::key::Secp256k1;
use bitcoin::key::rand::thread_rng;
use bitcoin::secp256k1::{self, PublicKey};
use fedimint_api_client::api::global_api::with_request_hook::ApiRequestHook;
use fedimint_api_client::api::{
    ApiVersionSet, DynGlobalApi, FederationApiExt as _, FederationResult, IGlobalFederationApi,
};
use fedimint_client_module::module::recovery::RecoveryProgress;
use fedimint_client_module::module::{
    ClientContextIface, ClientModule, ClientModuleRegistry, DynClientModule, FinalClientIface,
    IClientModule, IdxRange, OutPointRange, PrimaryModulePriority,
};
use fedimint_client_module::oplog::IOperationLog;
use fedimint_client_module::secret::{PlainRootSecretStrategy, RootSecretStrategy as _};
use fedimint_client_module::sm::executor::{ActiveStateKey, IExecutor, InactiveStateKey};
use fedimint_client_module::sm::{ActiveStateMeta, DynState, InactiveStateMeta};
use fedimint_client_module::transaction::{
    TRANSACTION_SUBMISSION_MODULE_INSTANCE, TransactionBuilder, TxSubmissionStates,
    TxSubmissionStatesSM,
};
use fedimint_client_module::{
    AddStateMachinesResult, ClientModuleInstance, GetInviteCodeRequest, ModuleGlobalContextGen,
    ModuleRecoveryCompleted, TransactionUpdates, TxCreatedEvent,
};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::{
    ClientConfig, FederationId, GlobalClientConfig, JsonClientConfig, ModuleInitRegistry,
};
use fedimint_core::core::{DynInput, DynOutput, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    AutocommitError, Database, DatabaseRecord, DatabaseTransaction,
    IDatabaseTransactionOpsCore as _, IDatabaseTransactionOpsCoreTyped as _, NonCommittable,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::endpoint_constants::{CLIENT_CONFIG_ENDPOINT, VERSION_ENDPOINT};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiRequestErased, ApiVersion, MultiApiVersion,
    SupportedApiVersionsSummary, SupportedCoreApiVersions, SupportedModuleApiVersions,
};
use fedimint_core::net::api_announcement::SignedApiAnnouncement;
use fedimint_core::runtime::sleep;
use fedimint_core::task::{Elapsed, MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::transaction::Transaction;
use fedimint_core::util::backoff_util::custom_backoff;
use fedimint_core::util::{
    BoxStream, FmtCompact as _, FmtCompactAnyhow as _, SafeUrl, backoff_util, retry,
};
use fedimint_core::{
    Amount, ChainId, NumPeers, OutPoint, PeerId, apply, async_trait_maybe_send, maybe_add_send,
    maybe_add_send_sync, runtime,
};
use fedimint_derive_secret::DerivableSecret;
use fedimint_eventlog::{
    DBTransactionEventLogExt as _, DynEventLogTrimableTracker, Event, EventKind, EventLogEntry,
    EventLogId, EventLogTrimableId, EventLogTrimableTracker, EventPersistence, PersistedLogEntry,
};
use fedimint_logging::{LOG_CLIENT, LOG_CLIENT_NET_API, LOG_CLIENT_RECOVERY};
use futures::stream::FuturesUnordered;
use futures::{Stream, StreamExt as _};
use global_ctx::ModuleGlobalClientContext;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tokio_stream::wrappers::WatchStream;
use tracing::{debug, info, warn};

use crate::ClientBuilder;
use crate::api_announcements::{ApiAnnouncementPrefix, get_api_urls};
use crate::backup::Metadata;
use crate::client::event_log::DefaultApplicationEventLogKey;
use crate::db::{
    ApiSecretKey, CachedApiVersionSet, CachedApiVersionSetKey, ChainIdKey,
    ChronologicalOperationLogKey, ClientConfigKey, ClientMetadataKey, ClientModuleRecovery,
    ClientModuleRecoveryState, EncodedClientSecretKey, OperationLogKey, PeerLastApiVersionsSummary,
    PeerLastApiVersionsSummaryKey, PendingClientConfigKey, apply_migrations_core_client_dbtx,
    get_decoded_client_secret, verify_client_db_integrity_dbtx,
};
use crate::meta::MetaService;
use crate::module_init::{ClientModuleInitRegistry, DynClientModuleInit, IClientModuleInit};
use crate::oplog::OperationLog;
use crate::sm::executor::{
    ActiveModuleOperationStateKeyPrefix, ActiveOperationStateKeyPrefix, Executor,
    InactiveModuleOperationStateKeyPrefix, InactiveOperationStateKeyPrefix,
};

pub(crate) mod builder;
pub(crate) mod event_log;
pub(crate) mod global_ctx;
pub(crate) mod handle;

/// List of core api versions supported by the implementation.
/// Notably `major` version is the one being supported, and corresponding
/// `minor` version is the one required (for given `major` version).
const SUPPORTED_CORE_API_VERSIONS: &[fedimint_core::module::ApiVersion] =
    &[ApiVersion { major: 0, minor: 0 }];

/// Primary module candidates at specific priority level
#[derive(Default)]
pub(crate) struct PrimaryModuleCandidates {
    /// Modules that listed specific units they handle
    specific: BTreeMap<AmountUnit, Vec<ModuleInstanceId>>,
    /// Modules handling any unit
    wildcard: Vec<ModuleInstanceId>,
}

/// Main client type
///
/// A handle and API to interacting with a single federation. End user
/// applications that want to support interacting with multiple federations at
/// the same time, will need to instantiate and manage multiple instances of
/// this struct.
///
/// Under the hood it is starting and managing service tasks, state machines,
/// database and other resources required.
///
/// This type is shared externally and internally, and
/// [`crate::ClientHandle`] is responsible for external lifecycle management
/// and resource freeing of the [`Client`].
pub struct Client {
    final_client: FinalClientIface,
    config: tokio::sync::RwLock<ClientConfig>,
    api_secret: Option<String>,
    decoders: ModuleDecoderRegistry,
    connectors: ConnectorRegistry,
    db: Database,
    federation_id: FederationId,
    federation_config_meta: BTreeMap<String, String>,
    primary_modules: BTreeMap<PrimaryModulePriority, PrimaryModuleCandidates>,
    pub(crate) modules: ClientModuleRegistry,
    module_inits: ClientModuleInitRegistry,
    executor: Executor,
    pub(crate) api: DynGlobalApi,
    root_secret: DerivableSecret,
    operation_log: OperationLog,
    secp_ctx: Secp256k1<secp256k1::All>,
    meta_service: Arc<MetaService>,

    task_group: TaskGroup,

    /// Updates about client recovery progress
    client_recovery_progress_receiver:
        watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryProgress>>,

    /// Internal client sender to wake up log ordering task every time a
    /// (unuordered) log event is added.
    log_ordering_wakeup_tx: watch::Sender<()>,
    /// Receiver for events fired every time (ordered) log event is added.
    log_event_added_rx: watch::Receiver<()>,
    log_event_added_transient_tx: broadcast::Sender<EventLogEntry>,
    request_hook: ApiRequestHook,
    iroh_enable_dht: bool,
    iroh_enable_next: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListOperationsParams {
    limit: Option<usize>,
    last_seen: Option<ChronologicalOperationLogKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOperationIdRequest {
    operation_id: OperationId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBalanceChangesRequest {
    #[serde(default = "AmountUnit::bitcoin")]
    unit: AmountUnit,
}

impl Client {
    /// Initialize a client builder that can be configured to create a new
    /// client.
    pub async fn builder() -> anyhow::Result<ClientBuilder> {
        Ok(ClientBuilder::new())
    }

    pub fn api(&self) -> &(dyn IGlobalFederationApi + 'static) {
        self.api.as_ref()
    }

    pub fn api_clone(&self) -> DynGlobalApi {
        self.api.clone()
    }

    /// Returns a stream that emits the current connection status of all peers
    /// whenever any peer's status changes. Emits initial state immediately.
    pub fn connection_status_stream(&self) -> impl Stream<Item = BTreeMap<PeerId, bool>> {
        self.api.connection_status_stream()
    }

    /// Get the [`TaskGroup`] that is tied to Client's lifetime.
    pub fn task_group(&self) -> &TaskGroup {
        &self.task_group
    }

    /// Returns all registered Prometheus metrics encoded in text format.
    ///
    /// This can be used by downstream clients to expose metrics via their own
    /// HTTP server or print them for debugging purposes.
    pub fn get_metrics() -> anyhow::Result<String> {
        fedimint_metrics::get_metrics()
    }

    /// Useful for our CLI tooling, not meant for external use
    #[doc(hidden)]
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    pub async fn get_config_from_db(db: &Database) -> Option<ClientConfig> {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&ClientConfigKey).await
    }

    pub async fn get_pending_config_from_db(db: &Database) -> Option<ClientConfig> {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&PendingClientConfigKey).await
    }

    pub async fn get_api_secret_from_db(db: &Database) -> Option<String> {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&ApiSecretKey).await
    }

    pub async fn store_encodable_client_secret<T: Encodable>(
        db: &Database,
        secret: T,
    ) -> anyhow::Result<()> {
        let mut dbtx = db.begin_transaction().await;

        // Don't overwrite an existing secret
        if dbtx.get_value(&EncodedClientSecretKey).await.is_some() {
            bail!("Encoded client secret already exists, cannot overwrite")
        }

        let encoded_secret = T::consensus_encode_to_vec(&secret);
        dbtx.insert_entry(&EncodedClientSecretKey, &encoded_secret)
            .await;
        dbtx.commit_tx().await;
        Ok(())
    }

    pub async fn load_decodable_client_secret<T: Decodable>(db: &Database) -> anyhow::Result<T> {
        let Some(secret) = Self::load_decodable_client_secret_opt(db).await? else {
            bail!("Encoded client secret not present in DB")
        };

        Ok(secret)
    }
    pub async fn load_decodable_client_secret_opt<T: Decodable>(
        db: &Database,
    ) -> anyhow::Result<Option<T>> {
        let mut dbtx = db.begin_transaction_nc().await;

        let client_secret = dbtx.get_value(&EncodedClientSecretKey).await;

        Ok(match client_secret {
            Some(client_secret) => Some(
                T::consensus_decode_whole(&client_secret, &ModuleRegistry::default())
                    .map_err(|e| anyhow!("Decoding failed: {e}"))?,
            ),
            None => None,
        })
    }

    pub async fn load_or_generate_client_secret(db: &Database) -> anyhow::Result<[u8; 64]> {
        let client_secret = match Self::load_decodable_client_secret::<[u8; 64]>(db).await {
            Ok(secret) => secret,
            _ => {
                let secret = PlainRootSecretStrategy::random(&mut thread_rng());
                Self::store_encodable_client_secret(db, secret)
                    .await
                    .expect("Storing client secret must work");
                secret
            }
        };
        Ok(client_secret)
    }

    pub async fn is_initialized(db: &Database) -> bool {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.raw_get_bytes(&[ClientConfigKey::DB_PREFIX])
            .await
            .expect("Unrecoverable error occurred while reading and entry from the database")
            .is_some()
    }

    pub fn start_executor(self: &Arc<Self>) {
        debug!(
            target: LOG_CLIENT,
            "Starting fedimint client executor",
        );
        self.executor.start_executor(self.context_gen());
    }

    pub fn federation_id(&self) -> FederationId {
        self.federation_id
    }

    fn context_gen(self: &Arc<Self>) -> ModuleGlobalContextGen {
        let client_inner = Arc::downgrade(self);
        Arc::new(move |module_instance, operation| {
            ModuleGlobalClientContext {
                client: client_inner
                    .clone()
                    .upgrade()
                    .expect("ModuleGlobalContextGen called after client was dropped"),
                module_instance_id: module_instance,
                operation,
            }
            .into()
        })
    }

    pub async fn config(&self) -> ClientConfig {
        self.config.read().await.clone()
    }

    // TODO: change to `-> Option<&str>`
    pub fn api_secret(&self) -> &Option<String> {
        &self.api_secret
    }

    /// Returns the core API version that the federation supports
    ///
    /// This reads from the cached version stored during client initialization.
    /// If no cache is available (e.g., during initial setup), returns a default
    /// version (0, 0).
    pub async fn core_api_version(&self) -> ApiVersion {
        // Try to get from cache. If not available, return a conservative
        // default. The cache should always be populated after successful client init.
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&CachedApiVersionSetKey)
            .await
            .map(|cached: CachedApiVersionSet| cached.0.core)
            .unwrap_or(ApiVersion { major: 0, minor: 0 })
    }

    /// Returns the chain ID (bitcoin block hash at height 1) from the
    /// federation
    ///
    /// This is cached in the database after the first successful fetch.
    /// The chain ID uniquely identifies which bitcoin network the federation
    /// operates on (mainnet, testnet, signet, regtest).
    pub async fn chain_id(&self) -> anyhow::Result<ChainId> {
        // Check cache first
        if let Some(chain_id) = self
            .db
            .begin_transaction_nc()
            .await
            .get_value(&ChainIdKey)
            .await
        {
            return Ok(chain_id);
        }

        // Fetch from federation with consensus
        let chain_id = self.api.chain_id().await?;

        // Cache the result
        let mut dbtx = self.db.begin_transaction().await;
        dbtx.insert_entry(&ChainIdKey, &chain_id).await;
        dbtx.commit_tx().await;

        Ok(chain_id)
    }

    pub fn decoders(&self) -> &ModuleDecoderRegistry {
        &self.decoders
    }

    /// Returns a reference to the module, panics if not found
    fn get_module(&self, instance: ModuleInstanceId) -> &maybe_add_send_sync!(dyn IClientModule) {
        self.try_get_module(instance)
            .expect("Module instance not found")
    }

    fn try_get_module(
        &self,
        instance: ModuleInstanceId,
    ) -> Option<&maybe_add_send_sync!(dyn IClientModule)> {
        Some(self.modules.get(instance)?.as_ref())
    }

    pub fn has_module(&self, instance: ModuleInstanceId) -> bool {
        self.modules.get(instance).is_some()
    }

    /// Returns the input amount and output amount of a transaction
    ///
    /// # Panics
    /// If any of the input or output versions in the transaction builder are
    /// unknown by the respective module.
    fn transaction_builder_get_balance(&self, builder: &TransactionBuilder) -> (Amounts, Amounts) {
        // FIXME: prevent overflows, currently not suitable for untrusted input
        let mut in_amounts = Amounts::ZERO;
        let mut out_amounts = Amounts::ZERO;
        let mut fee_amounts = Amounts::ZERO;

        for input in builder.inputs() {
            let module = self.get_module(input.input.module_instance_id());

            let item_fees = module.input_fee(&input.amounts, &input.input).expect(
                "We only build transactions with input versions that are supported by the module",
            );

            in_amounts.checked_add_mut(&input.amounts);
            fee_amounts.checked_add_mut(&item_fees);
        }

        for output in builder.outputs() {
            let module = self.get_module(output.output.module_instance_id());

            let item_fees = module.output_fee(&output.amounts, &output.output).expect(
                "We only build transactions with output versions that are supported by the module",
            );

            out_amounts.checked_add_mut(&output.amounts);
            fee_amounts.checked_add_mut(&item_fees);
        }

        out_amounts.checked_add_mut(&fee_amounts);
        (in_amounts, out_amounts)
    }

    pub fn get_internal_payment_markers(&self) -> anyhow::Result<(PublicKey, u64)> {
        Ok((self.federation_id().to_fake_ln_pub_key(&self.secp_ctx)?, 0))
    }

    /// Get metadata value from the federation config itself
    pub fn get_config_meta(&self, key: &str) -> Option<String> {
        self.federation_config_meta.get(key).cloned()
    }

    pub(crate) fn root_secret(&self) -> DerivableSecret {
        self.root_secret.clone()
    }

    pub async fn add_state_machines(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        states: Vec<DynState>,
    ) -> AddStateMachinesResult {
        self.executor.add_state_machines_dbtx(dbtx, states).await
    }

    // TODO: implement as part of [`OperationLog`]
    pub async fn get_active_operations(&self) -> HashSet<OperationId> {
        let active_states = self.executor.get_active_states().await;
        let mut active_operations = HashSet::with_capacity(active_states.len());
        let mut dbtx = self.db().begin_transaction_nc().await;
        for (state, _) in active_states {
            let operation_id = state.operation_id();
            if dbtx
                .get_value(&OperationLogKey { operation_id })
                .await
                .is_some()
            {
                active_operations.insert(operation_id);
            }
        }
        active_operations
    }

    pub fn operation_log(&self) -> &OperationLog {
        &self.operation_log
    }

    /// Get the meta manager to read meta fields.
    pub fn meta_service(&self) -> &Arc<MetaService> {
        &self.meta_service
    }

    /// Get the meta manager to read meta fields.
    pub async fn get_meta_expiration_timestamp(&self) -> Option<SystemTime> {
        let meta_service = self.meta_service();
        let ts = meta_service
            .get_field::<u64>(self.db(), "federation_expiry_timestamp")
            .await
            .and_then(|v| v.value)?;
        Some(UNIX_EPOCH + Duration::from_secs(ts))
    }

    /// Adds funding to a transaction or removes over-funding via change.
    async fn finalize_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        mut partial_transaction: TransactionBuilder,
    ) -> anyhow::Result<(Transaction, Vec<DynState>, Range<u64>)> {
        let (in_amounts, out_amounts) = self.transaction_builder_get_balance(&partial_transaction);

        let mut added_inputs_bundles = vec![];
        let mut added_outputs_bundles = vec![];

        // The way currently things are implemented is OK for modules which can
        // collect a fee relative to one being used, but will break down in any
        // fancy scenarios. Future TODOs:
        //
        // * create_final_inputs_and_outputs needs to get broken down, so we can use
        //   primary modules using priorities (possibly separate prios for inputs and
        //   outputs to be able to drain modules, etc.); we need the split "check if
        //   possible" and "take" steps,
        // * extra inputs and outputs adding fees needs to be taken into account,
        //   possibly with some looping
        for unit in in_amounts.units().union(&out_amounts.units()) {
            let input_amount = in_amounts.get(unit).copied().unwrap_or_default();
            let output_amount = out_amounts.get(unit).copied().unwrap_or_default();
            if input_amount == output_amount {
                continue;
            }

            let Some((module_id, module)) = self.primary_module_for_unit(*unit) else {
                bail!("No module to balance a partial transaction (affected unit: {unit:?}");
            };

            let (added_input_bundle, added_output_bundle) = module
                .create_final_inputs_and_outputs(
                    module_id,
                    dbtx,
                    operation_id,
                    *unit,
                    input_amount,
                    output_amount,
                )
                .await?;

            added_inputs_bundles.push(added_input_bundle);
            added_outputs_bundles.push(added_output_bundle);
        }

        // This is the range of  outputs that will be added to the transaction
        // in order to balance it. Notice that it may stay empty in case the transaction
        // is already balanced.
        let change_range = Range {
            start: partial_transaction.outputs().count() as u64,
            end: (partial_transaction.outputs().count() as u64
                + added_outputs_bundles
                    .iter()
                    .map(|output| output.outputs().len() as u64)
                    .sum::<u64>()),
        };

        for added_inputs in added_inputs_bundles {
            partial_transaction = partial_transaction.with_inputs(added_inputs);
        }

        for added_outputs in added_outputs_bundles {
            partial_transaction = partial_transaction.with_outputs(added_outputs);
        }

        let (input_amounts, output_amounts) =
            self.transaction_builder_get_balance(&partial_transaction);

        for (unit, output_amount) in output_amounts {
            let input_amount = input_amounts.get(&unit).copied().unwrap_or_default();

            assert!(input_amount >= output_amount, "Transaction is underfunded");
        }

        let (tx, states) = partial_transaction.build(&self.secp_ctx, thread_rng());

        Ok((tx, states, change_range))
    }

    /// Add funding and/or change to the transaction builder as needed, finalize
    /// the transaction and submit it to the federation.
    ///
    /// ## Errors
    /// The function will return an error if the operation with given ID already
    /// exists.
    ///
    /// ## Panics
    /// The function will panic if the database transaction collides with
    /// other and fails with others too often, this should not happen except for
    /// excessively concurrent scenarios.
    pub async fn finalize_and_submit_transaction<F, M>(
        &self,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta_gen: F,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<OutPointRange>
    where
        F: Fn(OutPointRange) -> M + Clone + MaybeSend + MaybeSync,
        M: serde::Serialize + MaybeSend,
    {
        let operation_type = operation_type.to_owned();

        let autocommit_res = self
            .db
            .autocommit(
                |dbtx, _| {
                    let operation_type = operation_type.clone();
                    let tx_builder = tx_builder.clone();
                    let operation_meta_gen = operation_meta_gen.clone();
                    Box::pin(async move {
                        if Client::operation_exists_dbtx(dbtx, operation_id).await {
                            bail!("There already exists an operation with id {operation_id:?}")
                        }

                        let out_point_range = self
                            .finalize_and_submit_transaction_inner(dbtx, operation_id, tx_builder)
                            .await?;

                        self.operation_log()
                            .add_operation_log_entry_dbtx(
                                dbtx,
                                operation_id,
                                &operation_type,
                                operation_meta_gen(out_point_range),
                            )
                            .await;

                        Ok(out_point_range)
                    })
                },
                Some(100), // TODO: handle what happens after 100 retries
            )
            .await;

        match autocommit_res {
            Ok(txid) => Ok(txid),
            Err(AutocommitError::ClosureError { error, .. }) => Err(error),
            Err(AutocommitError::CommitFailed {
                attempts,
                last_error,
            }) => panic!(
                "Failed to commit tx submission dbtx after {attempts} attempts: {last_error}"
            ),
        }
    }

    async fn finalize_and_submit_transaction_inner(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<OutPointRange> {
        let (transaction, mut states, change_range) = self
            .finalize_transaction(&mut dbtx.to_ref_nc(), operation_id, tx_builder)
            .await?;

        if transaction.consensus_encode_to_vec().len() > Transaction::MAX_TX_SIZE {
            let inputs = transaction
                .inputs
                .iter()
                .map(DynInput::module_instance_id)
                .collect::<Vec<_>>();
            let outputs = transaction
                .outputs
                .iter()
                .map(DynOutput::module_instance_id)
                .collect::<Vec<_>>();
            warn!(
                target: LOG_CLIENT_NET_API,
                size=%transaction.consensus_encode_to_vec().len(),
                ?inputs,
                ?outputs,
                "Transaction too large",
            );
            debug!(target: LOG_CLIENT_NET_API, ?transaction, "transaction details");
            bail!(
                "The generated transaction would be rejected by the federation for being too large."
            );
        }

        let txid = transaction.tx_hash();

        debug!(target: LOG_CLIENT_NET_API, %txid, ?transaction,  "Finalized and submitting transaction");

        let tx_submission_sm = DynState::from_typed(
            TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            TxSubmissionStatesSM {
                operation_id,
                state: TxSubmissionStates::Created(transaction),
            },
        );
        states.push(tx_submission_sm);

        self.executor.add_state_machines_dbtx(dbtx, states).await?;

        self.log_event_dbtx(dbtx, None, TxCreatedEvent { txid, operation_id })
            .await;

        Ok(OutPointRange::new(txid, IdxRange::from(change_range)))
    }

    async fn transaction_update_stream(
        &self,
        operation_id: OperationId,
    ) -> BoxStream<'static, TxSubmissionStatesSM> {
        self.executor
            .notifier()
            .module_notifier::<TxSubmissionStatesSM>(
                TRANSACTION_SUBMISSION_MODULE_INSTANCE,
                self.final_client.clone(),
            )
            .subscribe(operation_id)
            .await
    }

    pub async fn operation_exists(&self, operation_id: OperationId) -> bool {
        let mut dbtx = self.db().begin_transaction_nc().await;

        Client::operation_exists_dbtx(&mut dbtx, operation_id).await
    }

    pub async fn operation_exists_dbtx(
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
    ) -> bool {
        let active_state_exists = dbtx
            .find_by_prefix(&ActiveOperationStateKeyPrefix { operation_id })
            .await
            .next()
            .await
            .is_some();

        let inactive_state_exists = dbtx
            .find_by_prefix(&InactiveOperationStateKeyPrefix { operation_id })
            .await
            .next()
            .await
            .is_some();

        active_state_exists || inactive_state_exists
    }

    pub async fn has_active_states(&self, operation_id: OperationId) -> bool {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&ActiveOperationStateKeyPrefix { operation_id })
            .await
            .next()
            .await
            .is_some()
    }

    /// Waits for an output from the primary module to reach its final
    /// state.
    pub async fn await_primary_bitcoin_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<()> {
        self.primary_module_for_unit(AmountUnit::BITCOIN)
            .ok_or_else(|| anyhow!("No primary module available"))?
            .1
            .await_primary_module_output(operation_id, out_point)
            .await
    }

    /// Returns a reference to a typed module client instance by kind
    pub fn get_first_module<M: ClientModule>(
        &'_ self,
    ) -> anyhow::Result<ClientModuleInstance<'_, M>> {
        let module_kind = M::kind();
        let id = self
            .get_first_instance(&module_kind)
            .ok_or_else(|| format_err!("No modules found of kind {module_kind}"))?;
        let module: &M = self
            .try_get_module(id)
            .ok_or_else(|| format_err!("Unknown module instance {id}"))?
            .as_any()
            .downcast_ref::<M>()
            .ok_or_else(|| format_err!("Module is not of type {}", std::any::type_name::<M>()))?;
        let (db, _) = self.db().with_prefix_module_id(id);
        Ok(ClientModuleInstance {
            id,
            db,
            api: self.api().with_module(id),
            module,
        })
    }

    pub fn get_module_client_dyn(
        &self,
        instance_id: ModuleInstanceId,
    ) -> anyhow::Result<&maybe_add_send_sync!(dyn IClientModule)> {
        self.try_get_module(instance_id)
            .ok_or(anyhow!("Unknown module instance {}", instance_id))
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn endpoints(&self) -> &ConnectorRegistry {
        &self.connectors
    }

    /// Returns a stream of transaction updates for the given operation id that
    /// can later be used to watch for a specific transaction being accepted.
    pub async fn transaction_updates(&self, operation_id: OperationId) -> TransactionUpdates {
        TransactionUpdates {
            update_stream: self.transaction_update_stream(operation_id).await,
        }
    }

    /// Returns the instance id of the first module of the given kind.
    pub fn get_first_instance(&self, module_kind: &ModuleKind) -> Option<ModuleInstanceId> {
        self.modules
            .iter_modules()
            .find(|(_, kind, _module)| *kind == module_kind)
            .map(|(instance_id, _, _)| instance_id)
    }

    /// Returns the data from which the client's root secret is derived (e.g.
    /// BIP39 seed phrase struct).
    pub async fn root_secret_encoding<T: Decodable>(&self) -> anyhow::Result<T> {
        get_decoded_client_secret::<T>(self.db()).await
    }

    /// Waits for outputs from the primary module to reach its final
    /// state.
    pub async fn await_primary_bitcoin_module_outputs(
        &self,
        operation_id: OperationId,
        outputs: Vec<OutPoint>,
    ) -> anyhow::Result<()> {
        for out_point in outputs {
            self.await_primary_bitcoin_module_output(operation_id, out_point)
                .await?;
        }

        Ok(())
    }

    /// Returns the config of the client in JSON format.
    ///
    /// Compared to the consensus module format where module configs are binary
    /// encoded this format cannot be cryptographically verified but is easier
    /// to consume and to some degree human-readable.
    pub async fn get_config_json(&self) -> JsonClientConfig {
        self.config().await.to_json()
    }

    // Ideally this would not be in the API, but there's a lot of places where this
    // makes it easier.
    #[doc(hidden)]
    /// Like [`Self::get_balance`] but returns an error if primary module is not
    /// available
    pub async fn get_balance_for_btc(&self) -> anyhow::Result<Amount> {
        self.get_balance_for_unit(AmountUnit::BITCOIN).await
    }

    pub async fn get_balance_for_unit(&self, unit: AmountUnit) -> anyhow::Result<Amount> {
        let (id, module) = self
            .primary_module_for_unit(unit)
            .ok_or_else(|| anyhow!("Primary module not available"))?;
        Ok(module
            .get_balance(id, &mut self.db().begin_transaction_nc().await, unit)
            .await)
    }

    /// Returns a stream that yields the current client balance every time it
    /// changes.
    pub async fn subscribe_balance_changes(&self, unit: AmountUnit) -> BoxStream<'static, Amount> {
        let primary_module_things =
            if let Some((primary_module_id, primary_module)) = self.primary_module_for_unit(unit) {
                let balance_changes = primary_module.subscribe_balance_changes().await;
                let initial_balance = self
                    .get_balance_for_unit(unit)
                    .await
                    .expect("Primary is present");

                Some((
                    primary_module_id,
                    primary_module.clone(),
                    balance_changes,
                    initial_balance,
                ))
            } else {
                None
            };
        let db = self.db().clone();

        Box::pin(async_stream::stream! {
            let Some((primary_module_id, primary_module, mut balance_changes, initial_balance)) = primary_module_things else {
                // If there is no primary module, there will not be one until client is
                // restarted
                pending().await
            };


            yield initial_balance;
            let mut prev_balance = initial_balance;
            while let Some(()) = balance_changes.next().await {
                let mut dbtx = db.begin_transaction_nc().await;
                let balance = primary_module
                     .get_balance(primary_module_id, &mut dbtx, unit)
                    .await;

                // Deduplicate in case modules cannot always tell if the balance actually changed
                if balance != prev_balance {
                    prev_balance = balance;
                    yield balance;
                }
            }
        })
    }

    /// Make a single API version request to a peer after a delay.
    ///
    /// The delay is here to unify the type of a future both for initial request
    /// and possible retries.
    async fn make_api_version_request(
        delay: Duration,
        peer_id: PeerId,
        api: &DynGlobalApi,
    ) -> (
        PeerId,
        Result<SupportedApiVersionsSummary, fedimint_connectors::error::ServerError>,
    ) {
        runtime::sleep(delay).await;
        (
            peer_id,
            api.request_single_peer::<SupportedApiVersionsSummary>(
                VERSION_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
                peer_id,
            )
            .await,
        )
    }

    /// Create a backoff strategy for API version requests.
    ///
    /// Keep trying, initially somewhat aggressively, but after a while retry
    /// very slowly, because chances for response are getting lower and
    /// lower.
    fn create_api_version_backoff() -> impl Iterator<Item = Duration> {
        custom_backoff(Duration::from_millis(200), Duration::from_secs(600), None)
    }

    /// Query the federation for API version support and then calculate
    /// the best API version to use (supported by most guardians).
    pub async fn fetch_common_api_versions_from_all_peers(
        num_peers: NumPeers,
        api: DynGlobalApi,
        db: Database,
        num_responses_sender: watch::Sender<usize>,
    ) {
        let mut backoff = Self::create_api_version_backoff();

        // NOTE: `FuturesUnordered` is a footgun, but since we only poll it for result
        // and make a single async db write operation, it should be OK.
        let mut requests = FuturesUnordered::new();

        for peer_id in num_peers.peer_ids() {
            requests.push(Self::make_api_version_request(
                Duration::ZERO,
                peer_id,
                &api,
            ));
        }

        let mut num_responses = 0;

        while let Some((peer_id, response)) = requests.next().await {
            let retry = match response {
                Err(err) => {
                    let has_previous_response = db
                        .begin_transaction_nc()
                        .await
                        .get_value(&PeerLastApiVersionsSummaryKey(peer_id))
                        .await
                        .is_some();
                    debug!(
                        target: LOG_CLIENT,
                        %peer_id,
                        err = %err.fmt_compact(),
                        %has_previous_response,
                        "Failed to refresh API versions of a peer"
                    );

                    !has_previous_response
                }
                Ok(o) => {
                    // Save the response to the database right away, just to
                    // not lose it
                    let mut dbtx = db.begin_transaction().await;
                    dbtx.insert_entry(
                        &PeerLastApiVersionsSummaryKey(peer_id),
                        &PeerLastApiVersionsSummary(o),
                    )
                    .await;
                    dbtx.commit_tx().await;
                    false
                }
            };

            if retry {
                requests.push(Self::make_api_version_request(
                    backoff.next().expect("Keeps retrying"),
                    peer_id,
                    &api,
                ));
            } else {
                num_responses += 1;
                num_responses_sender.send_replace(num_responses);
            }
        }
    }

    /// Fetch API versions from peers, retrying until we get threshold number of
    /// successful responses. Returns the successful responses collected
    /// from at least `num_peers.threshold()` peers.
    pub async fn fetch_peers_api_versions_from_threshold_of_peers(
        num_peers: NumPeers,
        api: DynGlobalApi,
    ) -> BTreeMap<PeerId, SupportedApiVersionsSummary> {
        let mut backoff = Self::create_api_version_backoff();

        // NOTE: `FuturesUnordered` is a footgun, but since we only poll it for result
        // and collect responses, it should be OK.
        let mut requests = FuturesUnordered::new();

        for peer_id in num_peers.peer_ids() {
            requests.push(Self::make_api_version_request(
                Duration::ZERO,
                peer_id,
                &api,
            ));
        }

        let mut successful_responses = BTreeMap::new();

        while successful_responses.len() < num_peers.threshold()
            && let Some((peer_id, response)) = requests.next().await
        {
            let retry = match response {
                Err(err) => {
                    debug!(
                        target: LOG_CLIENT,
                        %peer_id,
                        err = %err.fmt_compact(),
                        "Failed to fetch API versions from peer"
                    );
                    true
                }
                Ok(response) => {
                    successful_responses.insert(peer_id, response);
                    false
                }
            };

            if retry {
                requests.push(Self::make_api_version_request(
                    backoff.next().expect("Keeps retrying"),
                    peer_id,
                    &api,
                ));
            }
        }

        successful_responses
    }

    /// Fetch API versions from peers and discover common API versions to use.
    pub async fn fetch_common_api_versions(
        config: &ClientConfig,
        api: &DynGlobalApi,
    ) -> anyhow::Result<BTreeMap<PeerId, SupportedApiVersionsSummary>> {
        debug!(
            target: LOG_CLIENT,
            "Fetching common api versions"
        );

        let num_peers = NumPeers::from(config.global.api_endpoints.len());

        let peer_api_version_sets =
            Self::fetch_peers_api_versions_from_threshold_of_peers(num_peers, api.clone()).await;

        Ok(peer_api_version_sets)
    }

    /// Write API version set to database cache.
    /// Used when we have a pre-calculated API version set that should be stored
    /// for later use.
    pub async fn write_api_version_cache(
        dbtx: &mut DatabaseTransaction<'_>,
        api_version_set: ApiVersionSet,
    ) {
        debug!(
            target: LOG_CLIENT,
            value = ?api_version_set,
            "Writing API version set to cache"
        );

        dbtx.insert_entry(
            &CachedApiVersionSetKey,
            &CachedApiVersionSet(api_version_set),
        )
        .await;
    }

    /// Store prefetched peer API version responses and calculate/store common
    /// API version set. This processes the individual peer responses by
    /// storing them in the database and calculating the common API version
    /// set for caching.
    pub async fn store_prefetched_api_versions(
        db: &Database,
        config: &ClientConfig,
        client_module_init: &ClientModuleInitRegistry,
        peer_api_versions: &BTreeMap<PeerId, SupportedApiVersionsSummary>,
    ) {
        debug!(
            target: LOG_CLIENT,
            "Storing {} prefetched peer API version responses and calculating common version set",
            peer_api_versions.len()
        );

        let mut dbtx = db.begin_transaction().await;
        // Calculate common API version set from individual responses
        let client_supported_versions =
            Self::supported_api_versions_summary_static(config, client_module_init);
        match fedimint_client_module::api_version_discovery::discover_common_api_versions_set(
            &client_supported_versions,
            peer_api_versions,
        ) {
            Ok(common_api_versions) => {
                // Write the calculated common API version set to database cache
                Self::write_api_version_cache(&mut dbtx.to_ref_nc(), common_api_versions).await;
                debug!(target: LOG_CLIENT, "Calculated and stored common API version set");
            }
            Err(err) => {
                debug!(target: LOG_CLIENT, err = %err.fmt_compact_anyhow(), "Failed to calculate common API versions from prefetched data");
            }
        }

        // Store individual peer responses to database
        for (peer_id, peer_api_versions) in peer_api_versions {
            dbtx.insert_entry(
                &PeerLastApiVersionsSummaryKey(*peer_id),
                &PeerLastApiVersionsSummary(peer_api_versions.clone()),
            )
            .await;
        }
        dbtx.commit_tx().await;
        debug!(target: LOG_CLIENT, "Stored individual peer API version responses");
    }

    /// [`SupportedApiVersionsSummary`] that the client and its modules support
    pub fn supported_api_versions_summary_static(
        config: &ClientConfig,
        client_module_init: &ClientModuleInitRegistry,
    ) -> SupportedApiVersionsSummary {
        SupportedApiVersionsSummary {
            core: SupportedCoreApiVersions {
                core_consensus: config.global.consensus_version,
                api: MultiApiVersion::try_from_iter(SUPPORTED_CORE_API_VERSIONS.to_owned())
                    .expect("must not have conflicting versions"),
            },
            modules: config
                .modules
                .iter()
                .filter_map(|(&module_instance_id, module_config)| {
                    client_module_init
                        .get(module_config.kind())
                        .map(|module_init| {
                            (
                                module_instance_id,
                                SupportedModuleApiVersions {
                                    core_consensus: config.global.consensus_version,
                                    module_consensus: module_config.version,
                                    api: module_init.supported_api_versions(),
                                },
                            )
                        })
                })
                .collect(),
        }
    }

    pub async fn load_and_refresh_common_api_version(&self) -> anyhow::Result<ApiVersionSet> {
        Self::load_and_refresh_common_api_version_static(
            &self.config().await,
            &self.module_inits,
            self.connectors.clone(),
            &self.api,
            &self.db,
            &self.task_group,
        )
        .await
    }

    /// Load the common api versions to use from cache and start a background
    /// process to refresh them.
    ///
    /// This is a compromise, so we not have to wait for version discovery to
    /// complete every time a [`Client`] is being built.
    async fn load_and_refresh_common_api_version_static(
        config: &ClientConfig,
        module_init: &ClientModuleInitRegistry,
        connectors: ConnectorRegistry,
        api: &DynGlobalApi,
        db: &Database,
        task_group: &TaskGroup,
    ) -> anyhow::Result<ApiVersionSet> {
        if let Some(v) = db
            .begin_transaction_nc()
            .await
            .get_value(&CachedApiVersionSetKey)
            .await
        {
            debug!(
                target: LOG_CLIENT,
                "Found existing cached common api versions"
            );
            let config = config.clone();
            let client_module_init = module_init.clone();
            let api = api.clone();
            let db = db.clone();
            let task_group = task_group.clone();
            // Separate task group, because we actually don't want to be waiting for this to
            // finish, and it's just best effort.
            task_group
                .clone()
                .spawn_cancellable("refresh_common_api_version_static", async move {
                    connectors.wait_for_initialized_connections().await;

                    if let Err(error) = Self::refresh_common_api_version_static(
                        &config,
                        &client_module_init,
                        &api,
                        &db,
                        task_group,
                        false,
                    )
                    .await
                    {
                        warn!(
                            target: LOG_CLIENT,
                            err = %error.fmt_compact_anyhow(), "Failed to discover common api versions"
                        );
                    }
                });

            return Ok(v.0);
        }

        info!(
            target: LOG_CLIENT,
            "Fetching initial API versions "
        );
        Self::refresh_common_api_version_static(
            config,
            module_init,
            api,
            db,
            task_group.clone(),
            true,
        )
        .await
    }

    async fn refresh_common_api_version_static(
        config: &ClientConfig,
        client_module_init: &ClientModuleInitRegistry,
        api: &DynGlobalApi,
        db: &Database,
        task_group: TaskGroup,
        block_until_ok: bool,
    ) -> anyhow::Result<ApiVersionSet> {
        debug!(
            target: LOG_CLIENT,
            "Refreshing common api versions"
        );

        let (num_responses_sender, mut num_responses_receiver) = tokio::sync::watch::channel(0);
        let num_peers = NumPeers::from(config.global.api_endpoints.len());

        task_group.spawn_cancellable("refresh peers api versions", {
            Client::fetch_common_api_versions_from_all_peers(
                num_peers,
                api.clone(),
                db.clone(),
                num_responses_sender,
            )
        });

        let common_api_versions = loop {
            // Wait to collect enough answers before calculating a set of common api
            // versions to use. Note that all peers individual responses from
            // previous attempts are still being used, and requests, or even
            // retries for response of peers are not actually cancelled, as they
            // are happening on a separate task. This is all just to bound the
            // time user can be waiting for the join operation to finish, at the
            // risk of picking wrong version in very rare circumstances.
            let _: Result<_, Elapsed> = runtime::timeout(
                Duration::from_secs(30),
                num_responses_receiver.wait_for(|num| num_peers.threshold() <= *num),
            )
            .await;

            let peer_api_version_sets = Self::load_peers_last_api_versions(db, num_peers).await;

            match fedimint_client_module::api_version_discovery::discover_common_api_versions_set(
                &Self::supported_api_versions_summary_static(config, client_module_init),
                &peer_api_version_sets,
            ) {
                Ok(o) => break o,
                Err(err) if block_until_ok => {
                    warn!(
                        target: LOG_CLIENT,
                        err = %err.fmt_compact_anyhow(),
                        "Failed to discover API version to use. Retrying..."
                    );
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        debug!(
            target: LOG_CLIENT,
            value = ?common_api_versions,
            "Updating the cached common api versions"
        );
        let mut dbtx = db.begin_transaction().await;
        let _ = dbtx
            .insert_entry(
                &CachedApiVersionSetKey,
                &CachedApiVersionSet(common_api_versions.clone()),
            )
            .await;

        dbtx.commit_tx().await;

        Ok(common_api_versions)
    }

    /// Get the client [`Metadata`]
    pub async fn get_metadata(&self) -> Metadata {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&ClientMetadataKey)
            .await
            .unwrap_or_else(|| {
                warn!(
                    target: LOG_CLIENT,
                    "Missing existing metadata. This key should have been set on Client init"
                );
                Metadata::empty()
            })
    }

    /// Set the client [`Metadata`]
    pub async fn set_metadata(&self, metadata: &Metadata) {
        self.db
            .autocommit::<_, _, anyhow::Error>(
                |dbtx, _| {
                    Box::pin(async {
                        Self::set_metadata_dbtx(dbtx, metadata).await;
                        Ok(())
                    })
                },
                None,
            )
            .await
            .expect("Failed to autocommit metadata");
    }

    pub fn has_pending_recoveries(&self) -> bool {
        !self
            .client_recovery_progress_receiver
            .borrow()
            .iter()
            .all(|(_id, progress)| progress.is_done())
    }

    /// Wait for all module recoveries to finish
    ///
    /// This will block until the recovery task is done with recoveries.
    /// Returns success if all recovery tasks are complete (success case),
    /// or an error if some modules could not complete the recovery at the time.
    ///
    /// A bit of a heavy approach.
    pub async fn wait_for_all_recoveries(&self) -> anyhow::Result<()> {
        let mut recovery_receiver = self.client_recovery_progress_receiver.clone();
        recovery_receiver
            .wait_for(|in_progress| {
                in_progress
                    .iter()
                    .all(|(_id, progress)| progress.is_done())
            })
            .await
            .context("Recovery task completed and update receiver disconnected, but some modules failed to recover")?;

        Ok(())
    }

    /// Subscribe to recover progress for all the modules.
    ///
    /// This stream can contain duplicate progress for a module.
    /// Don't use this stream for detecting completion of recovery.
    pub fn subscribe_to_recovery_progress(
        &self,
    ) -> impl Stream<Item = (ModuleInstanceId, RecoveryProgress)> + use<> {
        WatchStream::new(self.client_recovery_progress_receiver.clone())
            .flat_map(futures::stream::iter)
    }

    pub async fn wait_for_module_kind_recovery(
        &self,
        module_kind: ModuleKind,
    ) -> anyhow::Result<()> {
        let mut recovery_receiver = self.client_recovery_progress_receiver.clone();
        let config = self.config().await;
        recovery_receiver
            .wait_for(|in_progress| {
                !in_progress
                    .iter()
                    .filter(|(module_instance_id, _progress)| {
                        config.modules[module_instance_id].kind == module_kind
                    })
                    .any(|(_id, progress)| !progress.is_done())
            })
            .await
            .context("Recovery task completed and update receiver disconnected, but the desired modules are still unavailable or failed to recover")?;

        Ok(())
    }

    pub async fn wait_for_all_active_state_machines(&self) -> anyhow::Result<()> {
        loop {
            if self.executor.get_active_states().await.is_empty() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    /// Set the client [`Metadata`]
    pub async fn set_metadata_dbtx(dbtx: &mut DatabaseTransaction<'_>, metadata: &Metadata) {
        dbtx.insert_new_entry(&ClientMetadataKey, metadata).await;
    }

    fn spawn_module_recoveries_task(
        &self,
        recovery_sender: watch::Sender<BTreeMap<ModuleInstanceId, RecoveryProgress>>,
        module_recoveries: BTreeMap<
            ModuleInstanceId,
            Pin<Box<maybe_add_send!(dyn Future<Output = anyhow::Result<()>>)>>,
        >,
        module_recovery_progress_receivers: BTreeMap<
            ModuleInstanceId,
            watch::Receiver<RecoveryProgress>,
        >,
    ) {
        let db = self.db.clone();
        let log_ordering_wakeup_tx = self.log_ordering_wakeup_tx.clone();
        self.task_group
            .spawn("module recoveries", |_task_handle| async {
                Self::run_module_recoveries_task(
                    db,
                    log_ordering_wakeup_tx,
                    recovery_sender,
                    module_recoveries,
                    module_recovery_progress_receivers,
                )
                .await;
            });
    }

    async fn run_module_recoveries_task(
        db: Database,
        log_ordering_wakeup_tx: watch::Sender<()>,
        recovery_sender: watch::Sender<BTreeMap<ModuleInstanceId, RecoveryProgress>>,
        module_recoveries: BTreeMap<
            ModuleInstanceId,
            Pin<Box<maybe_add_send!(dyn Future<Output = anyhow::Result<()>>)>>,
        >,
        module_recovery_progress_receivers: BTreeMap<
            ModuleInstanceId,
            watch::Receiver<RecoveryProgress>,
        >,
    ) {
        debug!(target: LOG_CLIENT_RECOVERY, num_modules=%module_recovery_progress_receivers.len(), "Staring module recoveries");
        let mut completed_stream = Vec::new();
        let progress_stream = futures::stream::FuturesUnordered::new();

        for (module_instance_id, f) in module_recoveries {
            completed_stream.push(futures::stream::once(Box::pin(async move {
                match f.await {
                    Ok(()) => (module_instance_id, None),
                    Err(err) => {
                        warn!(
                            target: LOG_CLIENT,
                            err = %err.fmt_compact_anyhow(), module_instance_id, "Module recovery failed"
                        );
                        // a module recovery that failed reports and error and
                        // just never finishes, so we don't need a separate state
                        // for it
                        futures::future::pending::<()>().await;
                        unreachable!()
                    }
                }
            })));
        }

        for (module_instance_id, rx) in module_recovery_progress_receivers {
            progress_stream.push(
                tokio_stream::wrappers::WatchStream::new(rx)
                    .fuse()
                    .map(move |progress| (module_instance_id, Some(progress))),
            );
        }

        let mut futures = futures::stream::select(
            futures::stream::select_all(progress_stream),
            futures::stream::select_all(completed_stream),
        );

        while let Some((module_instance_id, progress)) = futures.next().await {
            let mut dbtx = db.begin_transaction().await;

            let prev_progress = *recovery_sender
                .borrow()
                .get(&module_instance_id)
                .expect("existing progress must be present");

            let progress = if prev_progress.is_done() {
                // since updates might be out of order, once done, stick with it
                prev_progress
            } else if let Some(progress) = progress {
                progress
            } else {
                prev_progress.to_complete()
            };

            if !prev_progress.is_done() && progress.is_done() {
                info!(
                    target: LOG_CLIENT,
                    module_instance_id,
                    progress = format!("{}/{}", progress.complete, progress.total),
                    "Recovery complete"
                );
                dbtx.log_event(
                    log_ordering_wakeup_tx.clone(),
                    None,
                    ModuleRecoveryCompleted {
                        module_id: module_instance_id,
                    },
                )
                .await;
            } else {
                info!(
                    target: LOG_CLIENT,
                    module_instance_id,
                    progress = format!("{}/{}", progress.complete, progress.total),
                    "Recovery progress"
                );
            }

            dbtx.insert_entry(
                &ClientModuleRecovery { module_instance_id },
                &ClientModuleRecoveryState { progress },
            )
            .await;
            dbtx.commit_tx().await;

            recovery_sender.send_modify(|v| {
                v.insert(module_instance_id, progress);
            });
        }
        debug!(target: LOG_CLIENT_RECOVERY, "Recovery executor stopped");
    }

    async fn load_peers_last_api_versions(
        db: &Database,
        num_peers: NumPeers,
    ) -> BTreeMap<PeerId, SupportedApiVersionsSummary> {
        let mut peer_api_version_sets = BTreeMap::new();

        let mut dbtx = db.begin_transaction_nc().await;
        for peer_id in num_peers.peer_ids() {
            if let Some(v) = dbtx
                .get_value(&PeerLastApiVersionsSummaryKey(peer_id))
                .await
            {
                peer_api_version_sets.insert(peer_id, v.0);
            }
        }
        drop(dbtx);
        peer_api_version_sets
    }

    /// You likely want to use [`Client::get_peer_urls`]. This function returns
    /// only the announcements and doesn't use the config as fallback.
    pub async fn get_peer_url_announcements(&self) -> BTreeMap<PeerId, SignedApiAnnouncement> {
        self.db()
            .begin_transaction_nc()
            .await
            .find_by_prefix(&ApiAnnouncementPrefix)
            .await
            .map(|(announcement_key, announcement)| (announcement_key.0, announcement))
            .collect()
            .await
    }

    /// Returns a list of guardian API URLs
    pub async fn get_peer_urls(&self) -> BTreeMap<PeerId, SafeUrl> {
        get_api_urls(&self.db, &self.config().await).await
    }

    /// Create an invite code with the api endpoint of the given peer which can
    /// be used to download this client config
    pub async fn invite_code(&self, peer: PeerId) -> Option<InviteCode> {
        self.get_peer_urls()
            .await
            .into_iter()
            .find_map(|(peer_id, url)| (peer == peer_id).then_some(url))
            .map(|peer_url| {
                InviteCode::new(
                    peer_url.clone(),
                    peer,
                    self.federation_id(),
                    self.api_secret.clone(),
                )
            })
    }

    /// Blocks till the client has synced the guardian public key set
    /// (introduced in version 0.4) and returns it. Once it has been fetched
    /// once this function is guaranteed to return immediately.
    pub async fn get_guardian_public_keys_blocking(
        &self,
    ) -> BTreeMap<PeerId, fedimint_core::secp256k1::PublicKey> {
        self.db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async move {
                        let config = self.config().await;

                        let guardian_pub_keys = self
                            .get_or_backfill_broadcast_public_keys(dbtx, config)
                            .await;

                        Result::<_, ()>::Ok(guardian_pub_keys)
                    })
                },
                None,
            )
            .await
            .expect("Will retry forever")
    }

    async fn get_or_backfill_broadcast_public_keys(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        config: ClientConfig,
    ) -> BTreeMap<PeerId, PublicKey> {
        match config.global.broadcast_public_keys {
            Some(guardian_pub_keys) => guardian_pub_keys,
            _ => {
                let (guardian_pub_keys, new_config) = self.fetch_and_update_config(config).await;

                dbtx.insert_entry(&ClientConfigKey, &new_config).await;
                *(self.config.write().await) = new_config;
                guardian_pub_keys
            }
        }
    }

    async fn fetch_session_count(&self) -> FederationResult<u64> {
        self.api.session_count().await
    }

    async fn fetch_and_update_config(
        &self,
        config: ClientConfig,
    ) -> (BTreeMap<PeerId, PublicKey>, ClientConfig) {
        let fetched_config = retry(
            "Fetching guardian public keys",
            backoff_util::background_backoff(),
            || async {
                Ok(self
                    .api
                    .request_current_consensus::<ClientConfig>(
                        CLIENT_CONFIG_ENDPOINT.to_owned(),
                        ApiRequestErased::default(),
                    )
                    .await?)
            },
        )
        .await
        .expect("Will never return on error");

        let Some(guardian_pub_keys) = fetched_config.global.broadcast_public_keys else {
            warn!(
                target: LOG_CLIENT,
                "Guardian public keys not found in fetched config, server not updated to 0.4 yet"
            );
            pending::<()>().await;
            unreachable!("Pending will never return");
        };

        let new_config = ClientConfig {
            global: GlobalClientConfig {
                broadcast_public_keys: Some(guardian_pub_keys.clone()),
                ..config.global
            },
            modules: config.modules,
        };
        (guardian_pub_keys, new_config)
    }

    pub fn handle_global_rpc(
        &self,
        method: String,
        params: serde_json::Value,
    ) -> BoxStream<'_, anyhow::Result<serde_json::Value>> {
        Box::pin(try_stream! {
            match method.as_str() {
                "get_balance" => {
                    let balance = self.get_balance_for_btc().await.unwrap_or_default();
                    yield serde_json::to_value(balance)?;
                }
                "subscribe_balance_changes" => {
                    let req: GetBalanceChangesRequest= serde_json::from_value(params)?;
                    let mut stream = self.subscribe_balance_changes(req.unit).await;
                    while let Some(balance) = stream.next().await {
                        yield serde_json::to_value(balance)?;
                    }
                }
                "get_config" => {
                    let config = self.config().await;
                    yield serde_json::to_value(config)?;
                }
                "get_federation_id" => {
                    let federation_id = self.federation_id();
                    yield serde_json::to_value(federation_id)?;
                }
                "get_invite_code" => {
                    let req: GetInviteCodeRequest = serde_json::from_value(params)?;
                    let invite_code = self.invite_code(req.peer).await;
                    yield serde_json::to_value(invite_code)?;
                }
                "get_operation" => {
                    let req: GetOperationIdRequest = serde_json::from_value(params)?;
                    let operation = self.operation_log().get_operation(req.operation_id).await;
                    yield serde_json::to_value(operation)?;
                }
                "list_operations" => {
                    let req: ListOperationsParams = serde_json::from_value(params)?;
                    let limit = if req.limit.is_none() && req.last_seen.is_none() {
                        usize::MAX
                    } else {
                        req.limit.unwrap_or(usize::MAX)
                    };
                    let operations = self.operation_log()
                        .paginate_operations_rev(limit, req.last_seen)
                        .await;
                    yield serde_json::to_value(operations)?;
                }
                "session_count" => {
                    let count = self.fetch_session_count().await?;
                    yield serde_json::to_value(count)?;
                }
                "has_pending_recoveries" => {
                    let has_pending = self.has_pending_recoveries();
                    yield serde_json::to_value(has_pending)?;
                }
                "wait_for_all_recoveries" => {
                    self.wait_for_all_recoveries().await?;
                    yield serde_json::Value::Null;
                }
                "subscribe_to_recovery_progress" => {
                    let mut stream = self.subscribe_to_recovery_progress();
                    while let Some((module_id, progress)) = stream.next().await {
                        yield serde_json::json!({
                            "module_id": module_id,
                            "progress": progress
                        });
                    }
                }
                #[allow(deprecated)]
                "backup_to_federation" => {
                    let metadata = if params.is_null() {
                        Metadata::from_json_serialized(serde_json::json!({}))
                    } else {
                        Metadata::from_json_serialized(params)
                    };
                    self.backup_to_federation(metadata).await?;
                    yield serde_json::Value::Null;
                }
                _ => {
                    Err(anyhow::format_err!("Unknown method: {}", method))?;
                    unreachable!()
                },
            }
        })
    }

    pub async fn log_event<E>(&self, module_id: Option<ModuleInstanceId>, event: E)
    where
        E: Event + Send,
    {
        let mut dbtx = self.db.begin_transaction().await;
        self.log_event_dbtx(&mut dbtx, module_id, event).await;
        dbtx.commit_tx().await;
    }

    pub async fn log_event_dbtx<E, Cap>(
        &self,
        dbtx: &mut DatabaseTransaction<'_, Cap>,
        module_id: Option<ModuleInstanceId>,
        event: E,
    ) where
        E: Event + Send,
        Cap: Send,
    {
        dbtx.log_event(self.log_ordering_wakeup_tx.clone(), module_id, event)
            .await;
    }

    pub async fn log_event_raw_dbtx<Cap>(
        &self,
        dbtx: &mut DatabaseTransaction<'_, Cap>,
        kind: EventKind,
        module: Option<(ModuleKind, ModuleInstanceId)>,
        payload: Vec<u8>,
        persist: EventPersistence,
    ) where
        Cap: Send,
    {
        let module_id = module.as_ref().map(|m| m.1);
        let module_kind = module.map(|m| m.0);
        dbtx.log_event_raw(
            self.log_ordering_wakeup_tx.clone(),
            kind,
            module_kind,
            module_id,
            payload,
            persist,
        )
        .await;
    }

    /// Built in event log (trimmable) tracker
    ///
    /// For the convenience of downstream applications, [`Client`] can store
    /// internally event log position for the main application using/driving it.
    ///
    /// Note that this position is a singleton, so this tracker should not be
    /// used for multiple purposes or applications, etc. at the same time.
    ///
    /// If the application has a need to follow log using multiple trackers, it
    /// should implement own [`DynEventLogTrimableTracker`] and store its
    /// persient data by itself.
    pub fn built_in_application_event_log_tracker(&self) -> DynEventLogTrimableTracker {
        struct BuiltInApplicationEventLogTracker;

        #[apply(async_trait_maybe_send!)]
        impl EventLogTrimableTracker for BuiltInApplicationEventLogTracker {
            // Store position in the event log
            async fn store(
                &mut self,
                dbtx: &mut DatabaseTransaction<NonCommittable>,
                pos: EventLogTrimableId,
            ) -> anyhow::Result<()> {
                dbtx.insert_entry(&DefaultApplicationEventLogKey, &pos)
                    .await;
                Ok(())
            }

            /// Load the last previous stored position (or None if never stored)
            async fn load(
                &mut self,
                dbtx: &mut DatabaseTransaction<NonCommittable>,
            ) -> anyhow::Result<Option<EventLogTrimableId>> {
                Ok(dbtx.get_value(&DefaultApplicationEventLogKey).await)
            }
        }
        Box::new(BuiltInApplicationEventLogTracker)
    }

    /// Like [`Self::handle_events`] but for historical data.
    ///
    ///
    /// This function can be used to process subset of events
    /// that is infrequent and important enough to be persisted
    /// forever. Most applications should prefer to use [`Self::handle_events`]
    /// which emits *all* events.
    pub async fn handle_historical_events<F, R>(
        &self,
        tracker: fedimint_eventlog::DynEventLogTracker,
        handler_fn: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(&mut DatabaseTransaction<NonCommittable>, EventLogEntry) -> R,
        R: Future<Output = anyhow::Result<()>>,
    {
        fedimint_eventlog::handle_events(
            self.db.clone(),
            tracker,
            self.log_event_added_rx.clone(),
            handler_fn,
        )
        .await
    }

    /// Handle events emitted by the client
    ///
    /// This is a preferred method for reactive & asynchronous
    /// processing of events emitted by the client.
    ///
    /// It needs a `tracker` that will persist the position in the log
    /// as it is being handled. You can use the
    /// [`Client::built_in_application_event_log_tracker`] if this call is
    /// used for the single main application handling this instance of the
    /// [`Client`]. Otherwise you should implement your own tracker.
    ///
    /// This handler will call `handle_fn` with ever event emitted by
    /// [`Client`], including transient ones. The caller should atomically
    /// handle each event it is interested in and ignore other ones.
    ///
    /// This method returns only when client is shutting down or on internal
    /// error, so typically should be called in a background task dedicated
    /// to handling events.
    pub async fn handle_events<F, R>(
        &self,
        tracker: fedimint_eventlog::DynEventLogTrimableTracker,
        handler_fn: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(&mut DatabaseTransaction<NonCommittable>, EventLogEntry) -> R,
        R: Future<Output = anyhow::Result<()>>,
    {
        fedimint_eventlog::handle_trimable_events(
            self.db.clone(),
            tracker,
            self.log_event_added_rx.clone(),
            handler_fn,
        )
        .await
    }

    pub async fn get_event_log(
        &self,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Vec<PersistedLogEntry> {
        self.get_event_log_dbtx(&mut self.db.begin_transaction_nc().await, pos, limit)
            .await
    }

    pub async fn get_event_log_trimable(
        &self,
        pos: Option<EventLogTrimableId>,
        limit: u64,
    ) -> Vec<PersistedLogEntry> {
        self.get_event_log_trimable_dbtx(&mut self.db.begin_transaction_nc().await, pos, limit)
            .await
    }

    pub async fn get_event_log_dbtx<Cap>(
        &self,
        dbtx: &mut DatabaseTransaction<'_, Cap>,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Vec<PersistedLogEntry>
    where
        Cap: Send,
    {
        dbtx.get_event_log(pos, limit).await
    }

    pub async fn get_event_log_trimable_dbtx<Cap>(
        &self,
        dbtx: &mut DatabaseTransaction<'_, Cap>,
        pos: Option<EventLogTrimableId>,
        limit: u64,
    ) -> Vec<PersistedLogEntry>
    where
        Cap: Send,
    {
        dbtx.get_event_log_trimable(pos, limit).await
    }

    /// Register to receiver all new transient (unpersisted) events
    pub fn get_event_log_transient_receiver(&self) -> broadcast::Receiver<EventLogEntry> {
        self.log_event_added_transient_tx.subscribe()
    }

    /// Get a receiver that signals when new events are added to the event log
    pub fn log_event_added_rx(&self) -> watch::Receiver<()> {
        self.log_event_added_rx.clone()
    }

    pub fn iroh_enable_dht(&self) -> bool {
        self.iroh_enable_dht
    }

    pub(crate) async fn run_core_migrations(
        db_no_decoders: &Database,
    ) -> Result<(), anyhow::Error> {
        let mut dbtx = db_no_decoders.begin_transaction().await;
        apply_migrations_core_client_dbtx(&mut dbtx.to_ref_nc(), "fedimint-client".to_string())
            .await?;
        if is_running_in_test_env() {
            verify_client_db_integrity_dbtx(&mut dbtx.to_ref_nc()).await;
        }
        dbtx.commit_tx_result().await?;
        Ok(())
    }

    /// Iterator over primary modules for a given `unit`
    fn primary_modules_for_unit(
        &self,
        unit: AmountUnit,
    ) -> impl Iterator<Item = (ModuleInstanceId, &DynClientModule)> {
        self.primary_modules
            .iter()
            .flat_map(move |(_prio, candidates)| {
                candidates
                    .specific
                    .get(&unit)
                    .into_iter()
                    .flatten()
                    .copied()
                    // within same priority, wildcard matches come last
                    .chain(candidates.wildcard.iter().copied())
            })
            .map(|id| (id, self.modules.get_expect(id)))
    }

    /// Primary module to use for `unit`
    ///
    /// Currently, just pick the first (highest priority) match
    pub fn primary_module_for_unit(
        &self,
        unit: AmountUnit,
    ) -> Option<(ModuleInstanceId, &DynClientModule)> {
        self.primary_modules_for_unit(unit).next()
    }

    /// [`Self::primary_module_for_unit`] for Bitcoin
    pub fn primary_module_for_btc(&self) -> (ModuleInstanceId, &DynClientModule) {
        self.primary_module_for_unit(AmountUnit::BITCOIN)
            .expect("No primary module for Bitcoin")
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientContextIface for Client {
    fn get_module(&self, instance: ModuleInstanceId) -> &maybe_add_send_sync!(dyn IClientModule) {
        Client::get_module(self, instance)
    }

    fn api_clone(&self) -> DynGlobalApi {
        Client::api_clone(self)
    }
    fn decoders(&self) -> &ModuleDecoderRegistry {
        Client::decoders(self)
    }

    async fn finalize_and_submit_transaction(
        &self,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta_gen: Box<maybe_add_send_sync!(dyn Fn(OutPointRange) -> serde_json::Value)>,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<OutPointRange> {
        Client::finalize_and_submit_transaction(
            self,
            operation_id,
            operation_type,
            // |out_point_range| operation_meta_gen(out_point_range),
            &operation_meta_gen,
            tx_builder,
        )
        .await
    }

    async fn finalize_and_submit_transaction_inner(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<OutPointRange> {
        Client::finalize_and_submit_transaction_inner(self, dbtx, operation_id, tx_builder).await
    }

    async fn transaction_updates(&self, operation_id: OperationId) -> TransactionUpdates {
        Client::transaction_updates(self, operation_id).await
    }

    async fn await_primary_module_outputs(
        &self,
        operation_id: OperationId,
        // TODO: make `impl Iterator<Item = ...>`
        outputs: Vec<OutPoint>,
    ) -> anyhow::Result<()> {
        Client::await_primary_bitcoin_module_outputs(self, operation_id, outputs).await
    }

    fn operation_log(&self) -> &dyn IOperationLog {
        Client::operation_log(self)
    }

    async fn has_active_states(&self, operation_id: OperationId) -> bool {
        Client::has_active_states(self, operation_id).await
    }

    async fn operation_exists(&self, operation_id: OperationId) -> bool {
        Client::operation_exists(self, operation_id).await
    }

    async fn config(&self) -> ClientConfig {
        Client::config(self).await
    }

    fn db(&self) -> &Database {
        Client::db(self)
    }

    fn executor(&self) -> &(maybe_add_send_sync!(dyn IExecutor + 'static)) {
        Client::executor(self)
    }

    async fn invite_code(&self, peer: PeerId) -> Option<InviteCode> {
        Client::invite_code(self, peer).await
    }

    fn get_internal_payment_markers(&self) -> anyhow::Result<(PublicKey, u64)> {
        Client::get_internal_payment_markers(self)
    }

    async fn log_event_json(
        &self,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        module_kind: Option<ModuleKind>,
        module_id: ModuleInstanceId,
        kind: EventKind,
        payload: serde_json::Value,
        persist: EventPersistence,
    ) {
        dbtx.ensure_global()
            .expect("Must be called with global dbtx");
        self.log_event_raw_dbtx(
            dbtx,
            kind,
            module_kind.map(|kind| (kind, module_id)),
            serde_json::to_vec(&payload).expect("Serialization can't fail"),
            persist,
        )
        .await;
    }

    async fn read_operation_active_states<'dbtx>(
        &self,
        operation_id: OperationId,
        module_id: ModuleInstanceId,
        dbtx: &'dbtx mut DatabaseTransaction<'_>,
    ) -> Pin<Box<maybe_add_send!(dyn Stream<Item = (ActiveStateKey, ActiveStateMeta)> + 'dbtx)>>
    {
        Box::pin(
            dbtx.find_by_prefix(&ActiveModuleOperationStateKeyPrefix {
                operation_id,
                module_instance: module_id,
            })
            .await
            .map(move |(k, v)| (k.0, v)),
        )
    }
    async fn read_operation_inactive_states<'dbtx>(
        &self,
        operation_id: OperationId,
        module_id: ModuleInstanceId,
        dbtx: &'dbtx mut DatabaseTransaction<'_>,
    ) -> Pin<Box<maybe_add_send!(dyn Stream<Item = (InactiveStateKey, InactiveStateMeta)> + 'dbtx)>>
    {
        Box::pin(
            dbtx.find_by_prefix(&InactiveModuleOperationStateKeyPrefix {
                operation_id,
                module_instance: module_id,
            })
            .await
            .map(move |(k, v)| (k.0, v)),
        )
    }
}

// TODO: impl `Debug` for `Client` and derive here
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client")
    }
}

pub fn client_decoders<'a>(
    registry: &ModuleInitRegistry<DynClientModuleInit>,
    module_kinds: impl Iterator<Item = (ModuleInstanceId, &'a ModuleKind)>,
) -> ModuleDecoderRegistry {
    let mut modules = BTreeMap::new();
    for (id, kind) in module_kinds {
        let Some(init) = registry.get(kind) else {
            debug!("Detected configuration for unsupported module id: {id}, kind: {kind}");
            continue;
        };

        modules.insert(
            id,
            (
                kind.clone(),
                IClientModuleInit::decoder(AsRef::<dyn IClientModuleInit + 'static>::as_ref(init)),
            ),
        );
    }
    ModuleDecoderRegistry::from(modules)
}
