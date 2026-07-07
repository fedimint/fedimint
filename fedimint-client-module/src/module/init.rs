pub mod recovery;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::bail;
use fedimint_api_client::api::{DynGlobalApi, DynModuleApi};
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleKind;
use fedimint_core::db::{Database, DatabaseVersion};
use fedimint_core::module::{ApiAuth, ApiVersion, CommonModuleInit, ModuleInit, MultiApiVersion};
use fedimint_core::task::{MaybeSend, ShuttingDownError, TaskGroup, TaskHandle};
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, ChainId, NumPeers, apply, async_trait_maybe_send};
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::LOG_CLIENT;
use tokio::sync::oneshot;
use tracing::{Span, warn};

use super::ClientContext;
use super::recovery::RecoveryProgress;
use crate::db::ClientModuleMigrationFn;
use crate::module::ClientModule;
use crate::sm::ModuleNotifier;

/// Factory function type for creating a Bitcoin RPC client from a chain ID.
///
/// This allows applications to provide their own Bitcoin RPC client
/// implementation based on the chain the federation operates on.
pub type BitcoindRpcFactory = Box<
    dyn FnOnce(ChainId) -> Pin<Box<dyn Future<Output = Option<DynBitcoindRpc>> + Send>>
        + Send
        + Sync,
>;

/// Factory function type for creating a Bitcoin RPC client from a URL.
///
/// This is used when the federation does not have ChainId support yet.
/// The factory receives a URL (typically from the module config) and can be
/// called to get an RPC client.
pub type BitcoindRpcNoChainIdFactory = Arc<
    dyn Fn(SafeUrl) -> Pin<Box<dyn Future<Output = Option<DynBitcoindRpc>> + Send>> + Send + Sync,
>;

pub struct ClientModuleInitArgs<C>
where
    C: ClientModuleInit,
{
    pub federation_id: FederationId,
    pub peer_num: usize,
    pub cfg: <<C as ModuleInit>::Common as CommonModuleInit>::ClientConfig,
    pub db: Database,
    pub core_api_version: ApiVersion,
    pub module_api_version: ApiVersion,
    pub module_root_secret: DerivableSecret,
    pub notifier: ModuleNotifier<<<C as ClientModuleInit>::Module as ClientModule>::States>,
    pub api: DynGlobalApi,
    pub admin_auth: Option<ApiAuth>,
    pub module_api: DynModuleApi,
    pub context: ClientContext<<C as ClientModuleInit>::Module>,
    pub task_group: TaskGroup,
    /// Long-lived span carrying `fed_id`. Use [`Self::spawn_cancellable`] /
    /// [`Self::spawn`] (or pass [`Self::client_span`] to
    /// [`TaskGroup::spawn_cancellable_with_span`]) so log events from
    /// background tasks carry the federation prefix.
    pub client_span: Span,
    pub connector_registry: ConnectorRegistry,
    /// User-provided Bitcoin RPC client
    ///
    /// If set by the application using `ClientBuilder::with_bitcoind_rpc`,
    /// modules (particularly the wallet module) can use this instead of
    /// creating their own Bitcoin RPC connection.
    pub user_bitcoind_rpc: Option<DynBitcoindRpc>,
    /// User-provided Bitcoin RPC factory for when ChainId is not available
    ///
    /// If set by the application using
    /// `ClientBuilder::with_bitcoind_rpc_no_chain_id`, modules can call
    /// this with a URL from their config to get an RPC client. This is used
    /// as a fallback when `user_bitcoind_rpc` is None.
    pub user_bitcoind_rpc_no_chain_id: Option<BitcoindRpcNoChainIdFactory>,
}

impl<C> ClientModuleInitArgs<C>
where
    C: ClientModuleInit,
{
    pub fn federation_id(&self) -> &FederationId {
        &self.federation_id
    }

    pub fn peer_num(&self) -> usize {
        self.peer_num
    }

    pub fn cfg(&self) -> &<<C as ModuleInit>::Common as CommonModuleInit>::ClientConfig {
        &self.cfg
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn core_api_version(&self) -> &ApiVersion {
        &self.core_api_version
    }

    pub fn module_api_version(&self) -> &ApiVersion {
        &self.module_api_version
    }

    pub fn module_root_secret(&self) -> &DerivableSecret {
        &self.module_root_secret
    }

    pub fn notifier(
        &self,
    ) -> &ModuleNotifier<<<C as ClientModuleInit>::Module as ClientModule>::States> {
        &self.notifier
    }

    pub fn api(&self) -> &DynGlobalApi {
        &self.api
    }

    pub fn admin_auth(&self) -> Option<&ApiAuth> {
        self.admin_auth.as_ref()
    }

    pub fn module_api(&self) -> &DynModuleApi {
        &self.module_api
    }

    /// Get the [`ClientContext`] for later use
    ///
    /// Notably `ClientContext` can not be used during `ClientModuleInit::init`,
    /// as the outer context is not yet complete. It can be stored for later use
    /// by [`ClientModule`] methods after startup completes. During
    /// [`ClientModule::pre_start_migration`] and [`ClientModule::start`],
    /// final-client paths are still unavailable; use the explicit pre-start
    /// migration context in the migration hook instead.
    pub fn context(&self) -> ClientContext<<C as ClientModuleInit>::Module> {
        self.context.clone()
    }

    pub fn task_group(&self) -> &TaskGroup {
        &self.task_group
    }

    /// Long-lived span identifying this client (with `fed_id`).
    pub fn client_span(&self) -> &Span {
        &self.client_span
    }

    /// Spawn a cancellable task on the client's task group, parented to the
    /// client's span so all events from the task carry `fed_id` (including
    /// the lifecycle events emitted by [`TaskGroup`] itself).
    pub fn spawn_cancellable<R>(
        &self,
        name: impl Into<String>,
        future: impl std::future::Future<Output = R> + MaybeSend + 'static,
    ) -> oneshot::Receiver<Result<R, ShuttingDownError>>
    where
        R: MaybeSend + 'static,
    {
        self.task_group
            .spawn_cancellable_with_span(self.client_span.clone(), name, future)
    }

    /// Spawn a task on the client's task group, parented to the client's span.
    pub fn spawn<Fut, R>(
        &self,
        name: impl Into<String>,
        f: impl FnOnce(TaskHandle) -> Fut + MaybeSend + 'static,
    ) -> oneshot::Receiver<R>
    where
        Fut: std::future::Future<Output = R> + MaybeSend + 'static,
        R: MaybeSend + 'static,
    {
        self.task_group
            .spawn_with_span(self.client_span.clone(), name, f)
    }

    pub fn connector_registry(&self) -> &ConnectorRegistry {
        &self.connector_registry
    }

    /// Returns the user-provided Bitcoin RPC client, if any
    ///
    /// Modules (particularly the wallet module) should check this first
    /// before creating their own Bitcoin RPC connection.
    pub fn user_bitcoind_rpc(&self) -> Option<&DynBitcoindRpc> {
        self.user_bitcoind_rpc.as_ref()
    }

    /// Returns the user-provided Bitcoin RPC factory for when ChainId is not
    /// available
    ///
    /// Modules can call this with a URL from their config to get an RPC client.
    /// This is used as a fallback when `user_bitcoind_rpc()` returns None.
    pub fn user_bitcoind_rpc_no_chain_id(&self) -> Option<&BitcoindRpcNoChainIdFactory> {
        self.user_bitcoind_rpc_no_chain_id.as_ref()
    }
}

/// How a module's recovery relates to using the module.
///
/// A recovering client runs a recovery for every module that has one, and only
/// the modules that can be used while that recovery runs join the module
/// registry; the rest become available once the client is reopened with their
/// recovery complete. This is a module's declaration of which of those it is,
/// returned from [`ClientModuleInit::recovery_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMode {
    /// The module implements no recovery.
    ///
    /// It is left out of a recovering client's recovery entirely: no recovery
    /// is started for it and it is initialized as it would be on any other
    /// client open, rather than being held back for a recovery that would do
    /// nothing.
    None,
    /// The module has a recovery and cannot be used while it runs.
    ///
    /// The recovery runs, but the module stays out of the module registry — and
    /// is therefore unusable — until the client is reopened with the recovery
    /// complete.
    Unusable,
    /// The module has a recovery and can be used while it runs.
    ///
    /// [`ClientModuleInit::prepare_recovery`] commits the boundary between the
    /// recovery and live operation, after which the module is initialized and
    /// usable straight away, with its recovery running in the background.
    Usable,
}

/// Arguments to [`ClientModuleInit::prepare_recovery`], which runs before the
/// module exists and so gets only what it takes to record where the recovery
/// ends and live operation begins.
pub struct ClientModuleRecoveryPrepareArgs {
    pub db: Database,
    pub module_api: DynModuleApi,
}

impl ClientModuleRecoveryPrepareArgs {
    /// Database isolated for this module instance
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Api of this module instance
    pub fn module_api(&self) -> &DynModuleApi {
        &self.module_api
    }
}

pub struct ClientModuleRecoverArgs<C>
where
    C: ClientModuleInit,
{
    pub federation_id: FederationId,
    pub num_peers: NumPeers,
    pub cfg: <<C as ModuleInit>::Common as CommonModuleInit>::ClientConfig,
    pub db: Database,
    pub core_api_version: ApiVersion,
    pub module_api_version: ApiVersion,
    pub module_root_secret: DerivableSecret,
    pub notifier: ModuleNotifier<<<C as ClientModuleInit>::Module as ClientModule>::States>,
    pub api: DynGlobalApi,
    pub admin_auth: Option<ApiAuth>,
    pub module_api: DynModuleApi,
    pub context: ClientContext<<C as ClientModuleInit>::Module>,
    pub progress_tx: tokio::sync::watch::Sender<RecoveryProgress>,
    pub task_group: TaskGroup,
    /// See [`ClientModuleInitArgs::client_span`].
    pub client_span: Span,
    /// User-provided Bitcoin RPC client
    ///
    /// If set by the application using `ClientBuilder::with_bitcoind_rpc`,
    /// modules (particularly the wallet module) can use this instead of
    /// creating their own Bitcoin RPC connection.
    pub user_bitcoind_rpc: Option<DynBitcoindRpc>,
    /// User-provided Bitcoin RPC factory for when ChainId is not available
    ///
    /// If set by the application using
    /// `ClientBuilder::with_bitcoind_rpc_no_chain_id`, modules can call
    /// this with a URL from their config to get an RPC client. This is used
    /// as a fallback when `user_bitcoind_rpc` is None.
    pub user_bitcoind_rpc_no_chain_id: Option<BitcoindRpcNoChainIdFactory>,
}

impl<C> ClientModuleRecoverArgs<C>
where
    C: ClientModuleInit,
{
    pub fn federation_id(&self) -> &FederationId {
        &self.federation_id
    }

    pub fn num_peers(&self) -> NumPeers {
        self.num_peers
    }

    pub fn cfg(&self) -> &<<C as ModuleInit>::Common as CommonModuleInit>::ClientConfig {
        &self.cfg
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn task_group(&self) -> &TaskGroup {
        &self.task_group
    }

    /// Long-lived span identifying this client (with `fed_id`).
    pub fn client_span(&self) -> &Span {
        &self.client_span
    }

    /// Spawn a cancellable task on the client's task group, parented to the
    /// client's span so all events from the task carry `fed_id`.
    pub fn spawn_cancellable<R>(
        &self,
        name: impl Into<String>,
        future: impl std::future::Future<Output = R> + MaybeSend + 'static,
    ) -> oneshot::Receiver<Result<R, ShuttingDownError>>
    where
        R: MaybeSend + 'static,
    {
        self.task_group
            .spawn_cancellable_with_span(self.client_span.clone(), name, future)
    }

    /// Spawn a task on the client's task group, parented to the client's span.
    pub fn spawn<Fut, R>(
        &self,
        name: impl Into<String>,
        f: impl FnOnce(TaskHandle) -> Fut + MaybeSend + 'static,
    ) -> oneshot::Receiver<R>
    where
        Fut: std::future::Future<Output = R> + MaybeSend + 'static,
        R: MaybeSend + 'static,
    {
        self.task_group
            .spawn_with_span(self.client_span.clone(), name, f)
    }

    pub fn core_api_version(&self) -> &ApiVersion {
        &self.core_api_version
    }

    pub fn module_api_version(&self) -> &ApiVersion {
        &self.module_api_version
    }

    pub fn module_root_secret(&self) -> &DerivableSecret {
        &self.module_root_secret
    }

    pub fn notifier(
        &self,
    ) -> &ModuleNotifier<<<C as ClientModuleInit>::Module as ClientModule>::States> {
        &self.notifier
    }

    pub fn api(&self) -> &DynGlobalApi {
        &self.api
    }

    pub fn admin_auth(&self) -> Option<&ApiAuth> {
        self.admin_auth.as_ref()
    }

    pub fn module_api(&self) -> &DynModuleApi {
        &self.module_api
    }

    /// Get the [`ClientContext`]
    ///
    /// Notably `ClientContext`, unlike [`ClientModuleInitArgs::context`],
    /// the client context is guaranteed to be usable immediately.
    pub fn context(&self) -> ClientContext<<C as ClientModuleInit>::Module> {
        self.context.clone()
    }

    pub fn update_recovery_progress(&self, progress: RecoveryProgress) {
        // we want a warning if the send channel was not connected to
        #[allow(clippy::disallowed_methods)]
        if progress.is_done() {
            // Recovery is complete when the recovery function finishes. To avoid
            // confusing any downstream code, we never send completed process.
            warn!(target: LOG_CLIENT, "Module trying to send a completed recovery progress. Ignoring");
        } else if progress.is_none() {
            // Recovery starts with "none" none progress. To avoid
            // confusing any downstream code, we never send none process afterwards.
            warn!(target: LOG_CLIENT, "Module trying to send a none recovery progress. Ignoring");
        } else if self.progress_tx.send(progress).is_err() {
            warn!(target: LOG_CLIENT, "Module trying to send a recovery progress but nothing is listening");
        }
    }

    /// Returns the user-provided Bitcoin RPC client, if any
    ///
    /// Modules (particularly the wallet module) should check this first
    /// before creating their own Bitcoin RPC connection.
    pub fn user_bitcoind_rpc(&self) -> Option<&DynBitcoindRpc> {
        self.user_bitcoind_rpc.as_ref()
    }

    /// Returns the user-provided Bitcoin RPC factory for when ChainId is not
    /// available
    ///
    /// Modules can call this with a URL from their config to get an RPC client.
    /// This is used as a fallback when `user_bitcoind_rpc()` returns None.
    pub fn user_bitcoind_rpc_no_chain_id(&self) -> Option<&BitcoindRpcNoChainIdFactory> {
        self.user_bitcoind_rpc_no_chain_id.as_ref()
    }
}

#[apply(async_trait_maybe_send!)]
pub trait ClientModuleInit: ModuleInit + Sized {
    type Module: ClientModule;

    /// Api versions of the corresponding server side module's API
    /// that this client module implementation can use.
    fn supported_api_versions(&self) -> MultiApiVersion;

    fn kind() -> ModuleKind {
        <Self::Module as ClientModule>::kind()
    }

    /// How this module's recovery relates to using the module, see
    /// [`RecoveryMode`].
    ///
    /// Must be overridden together with [`Self::recover`]: leaving this at
    /// [`RecoveryMode::None`] while implementing a recovery leaves that
    /// recovery unreachable, and overriding only this makes the module's
    /// recovery fail.
    fn recovery_mode(&self) -> RecoveryMode {
        RecoveryMode::None
    }

    /// Commit the boundary between a recovery and live operation.
    ///
    /// Called on every client open that starts or resumes a recovery, before
    /// [`Self::init`] and before the module joins the module registry.
    ///
    /// [`RecoveryMode::Usable`] is a claim that the recovery and the live
    /// module cannot interfere: the recovery must not rewrite state the module
    /// also writes, and must not rediscover what the live module is about to
    /// do. Whatever separates the two has to be recorded durably *here*,
    /// because everything after this point can run concurrently with the
    /// module. If this fails the client fails to open and neither the module
    /// nor its recovery is started, so [`Self::recover`] may rely on the
    /// boundary having been committed.
    ///
    /// Only called for modules whose [`Self::recovery_mode`] is
    /// [`RecoveryMode::Usable`].
    async fn prepare_recovery(
        &self,
        _args: &ClientModuleRecoveryPrepareArgs,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Recover the state of the client module, optionally from an existing
    /// snapshot.
    ///
    /// Only called for modules whose [`Self::recovery_mode`] is not
    /// [`RecoveryMode::None`].
    ///
    /// On success, returns the total amount recovered from this module, if the
    /// module tracks it (`None` for modules that can't determine the amount at
    /// recovery-completion time). This is surfaced in the
    /// `ModuleRecoveryCompleted` event.
    ///
    /// If `Err` is returned, the higher level client/application might try
    /// again at a different time (client restarted, code version changed, etc.)
    async fn recover(
        &self,
        _args: &ClientModuleRecoverArgs<Self>,
        _snapshot: Option<&<Self::Module as ClientModule>::Backup>,
    ) -> anyhow::Result<Option<Amount>> {
        bail!(
            "Module kind {} declares a recovery mode without implementing a recovery",
            <Self::Module as ClientModule>::kind()
        )
    }

    /// Initialize a [`ClientModule`] instance from its config
    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module>;

    /// Retrieves the database migrations from the module to be applied to the
    /// database before the module is initialized. The database migrations map
    /// is indexed on the "from" version.
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }

    /// Db prefixes used by the module
    ///
    /// If `Some` is returned, it should contain list of database
    /// prefixes actually used by the module for it's keys.
    ///
    /// In (some subset of) non-production tests,
    /// module database will be scanned for presence of keys
    /// that do not belong to this list to verify integrity
    /// of data and possibly catch any unforeseen bugs.
    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        None
    }
}
