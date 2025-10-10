use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context as _, anyhow, bail, ensure};
use bitcoin::key::Secp256k1;
use fedimint_api_client::api::global_api::with_cache::GlobalFederationApiWithCacheExt as _;
use fedimint_api_client::api::global_api::with_request_hook::{
    ApiRequestHook, RawFederationApiWithRequestHookExt as _,
};
use fedimint_api_client::api::net::Connector;
use fedimint_api_client::api::{
    ApiVersionSet, DynClientConnector, DynGlobalApi, FederationApiExt as _, ReconnectFederationApi,
    make_admin_connector, make_connector,
};
use fedimint_client_module::api::ClientRawFederationApiExt as _;
use fedimint_client_module::meta::LegacyMetaSource;
use fedimint_client_module::module::init::ClientModuleInit;
use fedimint_client_module::module::recovery::RecoveryProgress;
use fedimint_client_module::module::{ClientModuleRegistry, FinalClientIface};
use fedimint_client_module::secret::{DeriveableSecretClientExt as _, get_default_client_secret};
use fedimint_client_module::transaction::{
    TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionContext, tx_submission_sm_decoder,
};
use fedimint_client_module::{AdminCreds, ModuleRecoveryStarted};
use fedimint_core::config::{ClientConfig, FederationId, ModuleInitRegistry};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{
    Database, IDatabaseTransactionOpsCoreTyped as _, verify_module_db_integrity_dbtx,
};
use fedimint_core::endpoint_constants::CLIENT_CONFIG_ENDPOINT;
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiRequestErased, ApiVersion, SupportedApiVersionsSummary};
use fedimint_core::task::TaskGroup;
use fedimint_core::task::jit::{Jit, JitTry, JitTryAnyhow};
use fedimint_core::util::{FmtCompact as _, FmtCompactAnyhow as _};
use fedimint_core::{NumPeers, PeerId, fedimint_build_code_version_env, maybe_add_send};
use fedimint_derive_secret::DerivableSecret;
use fedimint_eventlog::{
    DBTransactionEventLogExt as _, EventLogEntry, run_event_log_ordering_task,
};
use fedimint_logging::LOG_CLIENT;
use tokio::sync::{broadcast, watch};
use tracing::{debug, trace, warn};

use super::handle::ClientHandle;
use super::{Client, client_decoders};
use crate::api_announcements::{
    PeersSignedApiAnnouncements, fetch_api_announcements_from_all_peers, get_api_urls,
    process_api_announcements, run_api_announcement_sync,
};
use crate::backup::{ClientBackup, Metadata};
use crate::db::{
    self, ApiSecretKey, ClientInitStateKey, ClientMetadataKey, ClientModuleRecovery,
    ClientModuleRecoveryState, ClientPreRootSecretHashKey, InitMode, InitState,
    PendingClientConfigKey, apply_migrations_client_module_dbtx,
};
use crate::meta::MetaService;
use crate::module_init::ClientModuleInitRegistry;
use crate::oplog::OperationLog;
use crate::sm::executor::Executor;
use crate::sm::notifier::Notifier;

/// The type of root secret hashing
///
/// *Please read this documentation carefully if, especially if you're upgrading
/// downstream Fedimint client application.*
///
/// Internally, client will always hash-in federation id
/// to the root secret provided to the [`ClientBuilder`],
/// to ensure a different actual root secret is used for ever federation.
/// This makes reusing a single root secret for different federations
/// in a multi-federation client, perfectly fine, and frees the client
/// from worrying about `FederationId`.
///
/// However, in the past Fedimint applications (including `fedimint-cli`)
/// were doing the hashing-in of `FederationId` outside of `fedimint-client` as
/// well, which lead to effectively doing it twice, and pushed downloading of
/// the client config on join to application code, a sub-optimal API, especially
/// after joining federation needed to handle even more functionality.
///
/// To keep the interoperability of the seed phrases this double-derivation
/// is preserved, due to other architectural reason, `fedimint-client`
/// will now do the outer-derivation internally as well.
#[derive(Clone)]
pub enum RootSecret {
    /// Derive an extra round of federation-id to the secret, like
    /// Fedimint applications were doing manually in the past.
    ///
    /// **Note**: Applications MUST NOT do the derivation themselves anymore.
    StandardDoubleDerive(DerivableSecret),
    /// No double derivation
    ///
    /// This is useful for applications that for whatever reason do the
    /// double-derivation externally, or use a custom scheme.
    Custom(DerivableSecret),
}

impl RootSecret {
    fn to_inner(&self, federation_id: FederationId) -> DerivableSecret {
        match self {
            RootSecret::StandardDoubleDerive(derivable_secret) => {
                get_default_client_secret(derivable_secret, &federation_id)
            }
            RootSecret::Custom(derivable_secret) => derivable_secret.clone(),
        }
    }
}

/// Used to configure, assemble and build [`Client`]
pub struct ClientBuilder {
    module_inits: ClientModuleInitRegistry,
    primary_module_instance: Option<ModuleInstanceId>,
    primary_module_kind: Option<ModuleKind>,
    admin_creds: Option<AdminCreds>,
    meta_service: Arc<crate::meta::MetaService>,
    connector: Connector,
    stopped: bool,
    log_event_added_transient_tx: broadcast::Sender<EventLogEntry>,
    request_hook: ApiRequestHook,
    reuse_connector: Option<DynClientConnector>,
    iroh_enable_dht: bool,
    iroh_enable_next: bool,
    task_group: TaskGroup,
}

impl ClientBuilder {
    pub(crate) fn new() -> Self {
        trace!(
            target: LOG_CLIENT,
            version = %fedimint_build_code_version_env!(),
            "Initializing fedimint client",
        );
        let meta_service = MetaService::new(LegacyMetaSource::default());
        let (log_event_added_transient_tx, _log_event_added_transient_rx) =
            broadcast::channel(1024);
        ClientBuilder {
            task_group: TaskGroup::new(),
            module_inits: ModuleInitRegistry::new(),
            primary_module_instance: None,
            primary_module_kind: None,
            connector: Connector::default(),
            admin_creds: None,
            stopped: false,
            meta_service,
            log_event_added_transient_tx,
            request_hook: Arc::new(|api| api),
            reuse_connector: None,
            iroh_enable_dht: true,
            iroh_enable_next: true,
        }
    }

    pub(crate) fn from_existing(client: &Client) -> Self {
        ClientBuilder {
            // Note: we don't want to keep running old clients tasks, etc.
            task_group: TaskGroup::new(),
            module_inits: client.module_inits.clone(),
            primary_module_instance: Some(client.primary_module_instance),
            primary_module_kind: None,
            admin_creds: None,
            stopped: false,
            // non unique
            meta_service: client.meta_service.clone(),
            connector: client.connector,
            log_event_added_transient_tx: client.log_event_added_transient_tx.clone(),
            request_hook: client.request_hook.clone(),
            reuse_connector: Some(client.api.connector().clone()),
            iroh_enable_dht: client.iroh_enable_dht,
            iroh_enable_next: client.iroh_enable_next,
        }
    }

    /// Replace module generator registry entirely
    ///
    /// There has to be at least one module supporting being primary among the
    /// registered modules. The client won't start without the federation and
    /// the client having at least one overlapping primary module. In case there
    /// are multiple, the one to use can be selected with
    /// [`ClientBuilder::with_primary_module_kind`] or
    /// [`ClientBuilder::with_primary_module_instance_id`].
    pub fn with_module_inits(&mut self, module_inits: ClientModuleInitRegistry) {
        self.module_inits = module_inits;
    }

    /// Make module generator available when reading the config
    ///
    /// There has to be at least one module supporting being primary among the
    /// registered modules. The client won't start without the federation and
    /// the client having at least one overlapping primary module. In case there
    /// are multiple, the one to use can be selected with
    /// [`ClientBuilder::with_primary_module_kind`] or
    /// [`ClientBuilder::with_primary_module_instance_id`].
    pub fn with_module<M: ClientModuleInit>(&mut self, module_init: M) {
        self.module_inits.attach(module_init);
    }

    pub fn stopped(&mut self) {
        self.stopped = true;
    }

    /// Build the [`Client`] with a custom wrapper around its api request logic
    ///
    /// This is intended to be used by downstream applications, e.g. to:
    ///
    /// * simulate offline mode,
    /// * save battery when the OS indicates lack of connectivity,
    /// * inject faults and delays for testing purposes,
    /// * collect statistics and emit notifications.
    pub fn with_api_request_hook(mut self, hook: ApiRequestHook) -> Self {
        self.request_hook = hook;
        self
    }

    /// Uses this module with the given instance id as the primary module. See
    /// [`fedimint_client_module::ClientModule::supports_being_primary`] for
    /// more information.
    ///
    /// ## Panics
    /// If there was a primary module specified previously
    #[deprecated(
        since = "0.6.0",
        note = "Use `with_primary_module_kind` instead, as the instance id can't be known upfront. If you *really* need the old behavior you can use `with_primary_module_instance_id`."
    )]
    pub fn with_primary_module(&mut self, primary_module_instance: ModuleInstanceId) {
        self.with_primary_module_instance_id(primary_module_instance);
    }

    /// **You are likely looking for
    /// [`ClientBuilder::with_primary_module_kind`]. This function is rarely
    /// useful and often dangerous, handle with care.**
    ///
    /// Uses this module with the given instance id as the primary module. See
    /// [`fedimint_client_module::ClientModule::supports_being_primary`] for
    /// more information. Since the module instance id of modules of a
    /// specific kind may differ between different federations it is
    /// generally not recommended to specify it, but rather to specify the
    /// module kind that should be used as primary. See
    /// [`ClientBuilder::with_primary_module_kind`].
    ///
    /// ## Panics
    /// If there was a primary module specified previously
    pub fn with_primary_module_instance_id(&mut self, primary_module_instance: ModuleInstanceId) {
        let was_replaced = self
            .primary_module_instance
            .replace(primary_module_instance)
            .is_some();
        assert!(
            !was_replaced,
            "Only one primary module can be given to the builder."
        );
    }

    /// Uses this module kind as the primary module if present in the config.
    /// See [`fedimint_client_module::ClientModule::supports_being_primary`] for
    /// more information.
    ///
    /// ## Panics
    /// If there was a primary module kind specified previously
    pub fn with_primary_module_kind(&mut self, primary_module_kind: ModuleKind) {
        let was_replaced = self
            .primary_module_kind
            .replace(primary_module_kind)
            .is_some();
        assert!(
            !was_replaced,
            "Only one primary module kind can be given to the builder."
        );
    }

    pub fn with_meta_service(&mut self, meta_service: Arc<MetaService>) {
        self.meta_service = meta_service;
    }

    /// Override if the DHT should be enabled when using Iroh to connect to
    /// the federation
    pub fn with_iroh_enable_dht(mut self, iroh_enable_dht: bool) -> Self {
        self.iroh_enable_dht = iroh_enable_dht;
        self
    }

    /// Override if the parallel unstable/next Iroh stack should be enabled when
    /// using Iroh to connect to the federation
    pub fn with_iroh_enable_next(mut self, iroh_enable_next: bool) -> Self {
        self.iroh_enable_next = iroh_enable_next;
        self
    }

    /// Migrate client module databases
    ///
    /// Note: Client core db migration are done immediately in
    /// [`Client::builder`], to ensure db matches the code at all times,
    /// while migrating modules requires figuring out what modules actually
    /// are first.
    async fn migrate_module_dbs(&self, db: &Database) -> anyhow::Result<()> {
        // Only apply the client database migrations if the database has been
        // initialized.
        // This only works as long as you don't change the client config
        if let Ok(client_config) = self.load_existing_config(db).await {
            for (module_id, module_cfg) in client_config.modules {
                let kind = module_cfg.kind.clone();
                let Some(init) = self.module_inits.get(&kind) else {
                    // normal, expected and already logged about when building the client
                    continue;
                };

                let mut dbtx = db.begin_transaction().await;
                apply_migrations_client_module_dbtx(
                    &mut dbtx.to_ref_nc(),
                    kind.to_string(),
                    init.get_database_migrations(),
                    module_id,
                )
                .await?;
                if let Some(used_db_prefixes) = init.used_db_prefixes()
                    && is_running_in_test_env()
                {
                    verify_module_db_integrity_dbtx(
                        &mut dbtx.to_ref_nc(),
                        module_id,
                        kind,
                        &used_db_prefixes,
                    )
                    .await;
                }
                dbtx.commit_tx_result().await?;
            }
        }

        Ok(())
    }

    pub async fn load_existing_config(&self, db: &Database) -> anyhow::Result<ClientConfig> {
        let Some(config) = Client::get_config_from_db(db).await else {
            bail!("Client database not initialized")
        };

        Ok(config)
    }

    pub fn set_admin_creds(&mut self, creds: AdminCreds) {
        self.admin_creds = Some(creds);
    }

    pub fn with_connector(&mut self, connector: Connector) {
        self.connector = connector;
    }

    #[cfg(feature = "tor")]
    pub fn with_tor_connector(&mut self) {
        self.with_connector(Connector::tor());
    }

    #[allow(clippy::too_many_arguments)]
    async fn init(
        self,
        db_no_decoders: Database,
        pre_root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
        init_mode: InitMode,
        preview_prefetch_api_announcements: Option<
            Jit<Vec<anyhow::Result<PeersSignedApiAnnouncements>>>,
        >,
        preview_prefetch_api_version_set: Option<
            JitTryAnyhow<BTreeMap<PeerId, SupportedApiVersionsSummary>>,
        >,
    ) -> anyhow::Result<ClientHandle> {
        if Client::is_initialized(&db_no_decoders).await {
            bail!("Client database already initialized")
        }

        Client::run_core_migrations(&db_no_decoders).await?;

        // Note: It's important all client initialization is performed as one big
        // transaction to avoid half-initialized client state.
        {
            debug!(target: LOG_CLIENT, "Initializing client database");
            let mut dbtx = db_no_decoders.begin_transaction().await;
            // Save config to DB
            dbtx.insert_new_entry(&crate::db::ClientConfigKey, &config)
                .await;
            dbtx.insert_entry(
                &ClientPreRootSecretHashKey,
                &pre_root_secret.derive_pre_root_secret_hash(),
            )
            .await;

            if let Some(api_secret) = api_secret.as_ref() {
                dbtx.insert_new_entry(&ApiSecretKey, api_secret).await;
            }

            let init_state = InitState::Pending(init_mode);
            dbtx.insert_entry(&ClientInitStateKey, &init_state).await;

            let metadata = init_state
                .does_require_recovery()
                .flatten()
                .map_or(Metadata::empty(), |s| s.metadata);

            dbtx.insert_new_entry(&ClientMetadataKey, &metadata).await;

            dbtx.commit_tx_result().await?;
        }

        let stopped = self.stopped;
        self.build(
            db_no_decoders,
            pre_root_secret,
            config,
            api_secret,
            stopped,
            preview_prefetch_api_announcements,
            preview_prefetch_api_version_set,
        )
        .await
    }

    pub async fn preview(self, invite_code: &InviteCode) -> anyhow::Result<ClientPreview> {
        let (config, api) = self
            .connector
            .download_from_invite_code(invite_code, self.iroh_enable_dht, self.iroh_enable_next)
            .await?;

        let prefetch_api_announcements =
            config
                .global
                .broadcast_public_keys
                .clone()
                .map(|guardian_pub_keys| {
                    Jit::new({
                        let api = api.clone();
                        || async move {
                            // Fetching api announcements using invite urls before joining, then
                            // write them to database This ensures the
                            // client can communicated with the
                            // Federation even if all the peers moved
                            fetch_api_announcements_from_all_peers(&api, &guardian_pub_keys).await
                        }
                    })
                });

        // refresh_api_announcement_sync(&api, &db, &guardian_pub_keys).await
        self.preview_inner(
            config,
            invite_code.api_secret(),
            Some(api),
            prefetch_api_announcements,
        )
        .await
    }

    /// Use [`Self::preview`] instead
    ///
    /// If `reuse_api` is set, it will allow the preview to prefetch some data
    /// to speed up the final join.
    pub async fn preview_with_existing_config(
        self,
        config: ClientConfig,
        api_secret: Option<String>,
        reuse_api: Option<DynGlobalApi>,
    ) -> anyhow::Result<ClientPreview> {
        self.preview_inner(config, api_secret, reuse_api, None)
            .await
    }

    async fn preview_inner(
        mut self,
        config: ClientConfig,
        api_secret: Option<String>,
        reuse_api: Option<DynGlobalApi>,
        prefetch_api_announcements: Option<Jit<Vec<anyhow::Result<PeersSignedApiAnnouncements>>>>,
    ) -> anyhow::Result<ClientPreview> {
        let preview_prefetch_api_version_set = if let Some(api) = reuse_api {
            self.reuse_connector = Some(api.connector().clone());

            Some(JitTry::new_try({
                let config = config.clone();
                || async move { Client::fetch_common_api_versions(&config, &api).await }
            }))
        } else {
            None
        };
        Ok(ClientPreview {
            inner: self,
            config,
            api_secret,
            prefetch_api_announcements,
            preview_prefetch_api_version_set,
        })
    }

    pub async fn open(
        self,
        db_no_decoders: Database,
        pre_root_secret: RootSecret,
    ) -> anyhow::Result<ClientHandle> {
        Client::run_core_migrations(&db_no_decoders).await?;

        // Check for pending config and migrate if present
        Self::migrate_pending_config_if_present(&db_no_decoders).await;

        let Some(config) = Client::get_config_from_db(&db_no_decoders).await else {
            bail!("Client database not initialized")
        };

        let pre_root_secret = pre_root_secret.to_inner(config.calculate_federation_id());

        match db_no_decoders
            .begin_transaction_nc()
            .await
            .get_value(&ClientPreRootSecretHashKey)
            .await
        {
            Some(secret_hash) => {
                ensure!(
                    pre_root_secret.derive_pre_root_secret_hash() == secret_hash,
                    "Secret hash does not match. Incorrect secret"
                );
            }
            _ => {
                debug!(target: LOG_CLIENT, "Backfilling secret hash");
                // Note: no need for dbtx autocommit, we are the only writer ATM
                let mut dbtx = db_no_decoders.begin_transaction().await;
                dbtx.insert_entry(
                    &ClientPreRootSecretHashKey,
                    &pre_root_secret.derive_pre_root_secret_hash(),
                )
                .await;
                dbtx.commit_tx().await;
            }
        }

        let api_secret = Client::get_api_secret_from_db(&db_no_decoders).await;
        let stopped = self.stopped;
        let request_hook = self.request_hook.clone();

        let log_event_added_transient_tx = self.log_event_added_transient_tx.clone();
        let client = self
            .build_stopped(
                db_no_decoders,
                pre_root_secret,
                &config,
                api_secret,
                log_event_added_transient_tx,
                request_hook,
                None,
                None,
            )
            .await?;
        if !stopped {
            client.as_inner().start_executor();
        }
        Ok(client)
    }

    /// Build a [`Client`] and start the executor
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn build(
        self,
        db_no_decoders: Database,
        pre_root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
        stopped: bool,
        preview_prefetch_api_announcements: Option<
            Jit<Vec<anyhow::Result<PeersSignedApiAnnouncements>>>,
        >,
        preview_prefetch_api_version_set: Option<
            JitTryAnyhow<BTreeMap<PeerId, SupportedApiVersionsSummary>>,
        >,
    ) -> anyhow::Result<ClientHandle> {
        let log_event_added_transient_tx = self.log_event_added_transient_tx.clone();
        let request_hook = self.request_hook.clone();
        let client = self
            .build_stopped(
                db_no_decoders,
                pre_root_secret,
                &config,
                api_secret,
                log_event_added_transient_tx,
                request_hook,
                preview_prefetch_api_announcements,
                preview_prefetch_api_version_set,
            )
            .await?;
        if !stopped {
            client.as_inner().start_executor();
        }

        Ok(client)
    }

    // TODO: remove config argument
    /// Build a [`Client`] but do not start the executor
    #[allow(clippy::too_many_arguments)]
    async fn build_stopped(
        self,
        db_no_decoders: Database,
        pre_root_secret: DerivableSecret,
        config: &ClientConfig,
        api_secret: Option<String>,
        log_event_added_transient_tx: broadcast::Sender<EventLogEntry>,
        request_hook: ApiRequestHook,
        preview_prefetch_api_announcements: Option<
            Jit<Vec<anyhow::Result<PeersSignedApiAnnouncements>>>,
        >,
        preview_prefetch_api_version_set: Option<
            JitTryAnyhow<BTreeMap<PeerId, SupportedApiVersionsSummary>>,
        >,
    ) -> anyhow::Result<ClientHandle> {
        debug!(
            target: LOG_CLIENT,
            version = %fedimint_build_code_version_env!(),
            "Building fedimint client",
        );
        let (log_event_added_tx, log_event_added_rx) = watch::channel(());
        let (log_ordering_wakeup_tx, log_ordering_wakeup_rx) = watch::channel(());

        let decoders = self.decoders(config);
        let config = Self::config_decoded(config, &decoders)?;
        let fed_id = config.calculate_federation_id();
        let db = db_no_decoders.with_decoders(decoders.clone());
        let connector = self.connector;
        let peer_urls = get_api_urls(&db, &config).await;
        let api = match self.admin_creds.as_ref() {
            Some(admin_creds) => {
                let connector = make_admin_connector(
                    admin_creds.peer_id,
                    peer_urls
                        .into_iter()
                        .find_map(|(peer, api_url)| {
                            (admin_creds.peer_id == peer).then_some(api_url)
                        })
                        .context("Admin creds should match a peer")?,
                    &api_secret,
                    self.iroh_enable_dht,
                    self.iroh_enable_next,
                )
                .await?;
                ReconnectFederationApi::new_admin(connector, admin_creds.peer_id)
                    .with_client_ext(db.clone(), log_ordering_wakeup_tx.clone())
                    .with_request_hook(&request_hook)
                    .with_cache()
                    .into()
            }
            None => {
                let connector = if let Some(connector) = self.reuse_connector.clone()
                    && connector.peers().len() == peer_urls.len()
                {
                    connector
                } else {
                    make_connector(
                        peer_urls,
                        &api_secret,
                        self.iroh_enable_dht,
                        self.iroh_enable_next,
                    )
                    .await?
                };
                ReconnectFederationApi::new(connector, None)
                    .with_client_ext(db.clone(), log_ordering_wakeup_tx.clone())
                    .with_request_hook(&request_hook)
                    .with_cache()
                    .into()
            }
        };

        // Migrate the database before interacting with it in case any on-disk data
        // structures have changed.
        self.migrate_module_dbs(&db).await?;

        let init_state = Self::load_init_state(&db).await;

        let mut primary_module_instance = self.primary_module_instance.or_else(|| {
            let primary_module_kind = self.primary_module_kind?;
            config
                .modules
                .iter()
                .find_map(|(module_instance_id, module_config)| {
                    (module_config.kind() == &primary_module_kind).then_some(*module_instance_id)
                })
        });

        let notifier = Notifier::new();

        if let Some(p) = preview_prefetch_api_announcements {
            // Unlike the api version set, we want to fail if we were unable to figure out
            // current addresses of peers in the federation, as it will potentially never
            // fix itself.
            let announcements = p.get().await;

            process_api_announcements(
                &db,
                config
                    .global
                    .broadcast_public_keys
                    .as_ref()
                    .expect("If announcements were fetched, the pubkeys must be there"),
                announcements,
            )
            .await?
        }

        if let Some(preview_prefetch_api_version_set) = preview_prefetch_api_version_set {
            match preview_prefetch_api_version_set.get_try().await {
                Ok(peer_api_versions) => {
                    Client::store_prefetched_api_versions(
                        &db,
                        &config,
                        &self.module_inits,
                        peer_api_versions,
                    )
                    .await;
                }
                Err(err) => {
                    debug!(target: LOG_CLIENT, err = %err.fmt_compact(), "Prefetching api version negotiation failed");
                }
            }
        }

        let common_api_versions = Client::load_and_refresh_common_api_version_static(
            &config,
            &self.module_inits,
            &api,
            &db,
            &self.task_group,
        )
        .await
        .inspect_err(|err| {
            warn!(target: LOG_CLIENT, err = %err.fmt_compact_anyhow(), "Failed to discover API version to use.");
        })
        .unwrap_or(ApiVersionSet {
            core: ApiVersion::new(0, 0),
            // This will cause all modules to skip initialization
            modules: BTreeMap::new(),
        });

        debug!(target: LOG_CLIENT, ?common_api_versions, "Completed api version negotiation");

        // Asynchronously refetch client config and compare with existing
        Self::load_and_refresh_client_config_static(&config, &api, &db, &self.task_group);

        let mut module_recoveries: BTreeMap<
            ModuleInstanceId,
            Pin<Box<maybe_add_send!(dyn Future<Output = anyhow::Result<()>>)>>,
        > = BTreeMap::new();
        let mut module_recovery_progress_receivers: BTreeMap<
            ModuleInstanceId,
            watch::Receiver<RecoveryProgress>,
        > = BTreeMap::new();

        let final_client = FinalClientIface::default();

        let root_secret = Self::federation_root_secret(&pre_root_secret, &config);

        let modules = {
            let mut modules = ClientModuleRegistry::default();
            for (module_instance_id, module_config) in config.modules.clone() {
                let kind = module_config.kind().clone();
                let Some(module_init) = self.module_inits.get(&kind).cloned() else {
                    debug!(
                        target: LOG_CLIENT,
                        kind=%kind,
                        instance_id=%module_instance_id,
                        "Module kind of instance not found in module gens, skipping");
                    continue;
                };

                let Some(&api_version) = common_api_versions.modules.get(&module_instance_id)
                else {
                    warn!(
                        target: LOG_CLIENT,
                        kind=%kind,
                        instance_id=%module_instance_id,
                        "Module kind of instance has incompatible api version, skipping"
                    );
                    continue;
                };

                // since the exact logic of when to start recovery is a bit gnarly,
                // the recovery call is extracted here.
                let start_module_recover_fn =
                    |snapshot: Option<ClientBackup>, progress: RecoveryProgress| {
                        let module_config = module_config.clone();
                        let num_peers = NumPeers::from(config.global.api_endpoints.len());
                        let db = db.clone();
                        let kind = kind.clone();
                        let notifier = notifier.clone();
                        let api = api.clone();
                        let root_secret = root_secret.clone();
                        let admin_auth = self.admin_creds.as_ref().map(|creds| creds.auth.clone());
                        let final_client = final_client.clone();
                        let (progress_tx, progress_rx) = tokio::sync::watch::channel(progress);
                        let task_group = self.task_group.clone();
                        let module_init = module_init.clone();
                        (
                            Box::pin(async move {
                                module_init
                                    .recover(
                                        final_client.clone(),
                                        fed_id,
                                        num_peers,
                                        module_config.clone(),
                                        db.clone(),
                                        module_instance_id,
                                        common_api_versions.core,
                                        api_version,
                                        root_secret.derive_module_secret(module_instance_id),
                                        notifier.clone(),
                                        api.clone(),
                                        admin_auth,
                                        snapshot.as_ref().and_then(|s| s.modules.get(&module_instance_id)),
                                        progress_tx,
                                        task_group,
                                    )
                                    .await
                                    .inspect_err(|err| {
                                        warn!(
                                            target: LOG_CLIENT,
                                            module_id = module_instance_id, %kind, err = %err.fmt_compact_anyhow(), "Module failed to recover"
                                        );
                                    })
                            }),
                            progress_rx,
                        )
                    };

                let recovery = match init_state.does_require_recovery() {
                    Some(snapshot) => {
                        match db
                            .begin_transaction_nc()
                            .await
                            .get_value(&ClientModuleRecovery { module_instance_id })
                            .await
                        {
                            Some(module_recovery_state) => {
                                if module_recovery_state.is_done() {
                                    debug!(
                                        id = %module_instance_id,
                                        %kind, "Module recovery already complete"
                                    );
                                    None
                                } else {
                                    debug!(
                                        id = %module_instance_id,
                                        %kind,
                                        progress = %module_recovery_state.progress,
                                        "Starting module recovery with an existing progress"
                                    );
                                    Some(start_module_recover_fn(
                                        snapshot,
                                        module_recovery_state.progress,
                                    ))
                                }
                            }
                            _ => {
                                let progress = RecoveryProgress::none();
                                let mut dbtx = db.begin_transaction().await;
                                dbtx.log_event(
                                    log_ordering_wakeup_tx.clone(),
                                    None,
                                    ModuleRecoveryStarted::new(module_instance_id),
                                )
                                .await;
                                dbtx.insert_entry(
                                    &ClientModuleRecovery { module_instance_id },
                                    &ClientModuleRecoveryState { progress },
                                )
                                .await;

                                dbtx.commit_tx().await;

                                debug!(
                                    id = %module_instance_id,
                                    %kind, "Starting new module recovery"
                                );
                                Some(start_module_recover_fn(snapshot, progress))
                            }
                        }
                    }
                    _ => None,
                };

                match recovery {
                    Some((recovery, recovery_progress_rx)) => {
                        module_recoveries.insert(module_instance_id, recovery);
                        module_recovery_progress_receivers
                            .insert(module_instance_id, recovery_progress_rx);
                    }
                    _ => {
                        let module = module_init
                            .init(
                                final_client.clone(),
                                fed_id,
                                config.global.api_endpoints.len(),
                                module_config,
                                db.clone(),
                                module_instance_id,
                                common_api_versions.core,
                                api_version,
                                // This is a divergence from the legacy client, where the child
                                // secret keys were derived using
                                // *module kind*-specific derivation paths.
                                // Since the new client has to support multiple, segregated modules
                                // of the same kind we have to use
                                // the instance id instead.
                                root_secret.derive_module_secret(module_instance_id),
                                notifier.clone(),
                                api.clone(),
                                self.admin_creds.as_ref().map(|cred| cred.auth.clone()),
                                self.task_group.clone(),
                            )
                            .await?;

                        if primary_module_instance.is_none() && module.supports_being_primary() {
                            primary_module_instance = Some(module_instance_id);
                        } else if primary_module_instance == Some(module_instance_id)
                            && !module.supports_being_primary()
                        {
                            bail!(
                                "Module instance {module_instance_id} of kind {kind} does not support being a primary module"
                            );
                        }

                        modules.register_module(module_instance_id, kind, module);
                    }
                }
            }
            modules
        };

        if init_state.is_pending() && module_recoveries.is_empty() {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(&ClientInitStateKey, &init_state.into_complete())
                .await;
            dbtx.commit_tx().await;
        }

        let executor = {
            let mut executor_builder = Executor::builder();
            executor_builder
                .with_module(TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionContext);

            for (module_instance_id, _, module) in modules.iter_modules() {
                executor_builder.with_module_dyn(module.context(module_instance_id));
            }

            for module_instance_id in module_recoveries.keys() {
                executor_builder.with_valid_module_id(*module_instance_id);
            }

            executor_builder.build(
                db.clone(),
                notifier,
                self.task_group.clone(),
                log_ordering_wakeup_tx.clone(),
            )
        };

        let recovery_receiver_init_val = module_recovery_progress_receivers
            .iter()
            .map(|(module_instance_id, rx)| (*module_instance_id, *rx.borrow()))
            .collect::<BTreeMap<_, _>>();
        let (client_recovery_progress_sender, client_recovery_progress_receiver) =
            watch::channel(recovery_receiver_init_val);

        let client_inner = Arc::new(Client {
            final_client: final_client.clone(),
            config: tokio::sync::RwLock::new(config.clone()),
            api_secret,
            decoders,
            db: db.clone(),
            federation_id: fed_id,
            federation_config_meta: config.global.meta,
            primary_module_instance: primary_module_instance
                .ok_or(anyhow!("No primary module set or found"))?,
            modules,
            module_inits: self.module_inits.clone(),
            log_ordering_wakeup_tx,
            log_event_added_rx,
            log_event_added_transient_tx: log_event_added_transient_tx.clone(),
            request_hook,
            executor,
            api,
            secp_ctx: Secp256k1::new(),
            root_secret,
            task_group: self.task_group,
            operation_log: OperationLog::new(db.clone()),
            client_recovery_progress_receiver,
            meta_service: self.meta_service,
            connector,
            iroh_enable_dht: self.iroh_enable_dht,
            iroh_enable_next: self.iroh_enable_next,
        });
        client_inner
            .task_group
            .spawn_cancellable("MetaService::update_continuously", {
                let client_inner = client_inner.clone();
                async move {
                    client_inner
                        .meta_service
                        .update_continuously(&client_inner)
                        .await;
                }
            });

        client_inner.task_group.spawn_cancellable(
            "update-api-announcements",
            run_api_announcement_sync(client_inner.clone()),
        );

        client_inner.task_group.spawn_cancellable(
            "event log ordering task",
            run_event_log_ordering_task(
                db.clone(),
                log_ordering_wakeup_rx,
                log_event_added_tx,
                log_event_added_transient_tx,
            ),
        );
        let client_iface = std::sync::Arc::<Client>::downgrade(&client_inner);

        let client_arc = ClientHandle::new(client_inner);

        for (_, _, module) in client_arc.modules.iter_modules() {
            module.start().await;
        }

        final_client.set(client_iface.clone());

        if !module_recoveries.is_empty() {
            client_arc.spawn_module_recoveries_task(
                client_recovery_progress_sender,
                module_recoveries,
                module_recovery_progress_receivers,
            );
        }

        Ok(client_arc)
    }

    async fn load_init_state(db: &Database) -> InitState {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&ClientInitStateKey)
            .await
            .unwrap_or_else(|| {
                // could be turned in a hard error in the future, but for now
                // no need to break backward compat.
                warn!(
                    target: LOG_CLIENT,
                    "Client missing ClientRequiresRecovery: assuming complete"
                );
                db::InitState::Complete(db::InitModeComplete::Fresh)
            })
    }

    fn decoders(&self, config: &ClientConfig) -> ModuleDecoderRegistry {
        let mut decoders = client_decoders(
            &self.module_inits,
            config
                .modules
                .iter()
                .map(|(module_instance, module_config)| (*module_instance, module_config.kind())),
        );

        decoders.register_module(
            TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            ModuleKind::from_static_str("tx_submission"),
            tx_submission_sm_decoder(),
        );

        decoders
    }

    fn config_decoded(
        config: &ClientConfig,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<ClientConfig, fedimint_core::encoding::DecodeError> {
        config.clone().redecode_raw(decoders)
    }

    /// Re-derive client's `root_secret` using the federation ID. This
    /// eliminates the possibility of having the same client `root_secret`
    /// across multiple federations.
    fn federation_root_secret(
        pre_root_secret: &DerivableSecret,
        config: &ClientConfig,
    ) -> DerivableSecret {
        pre_root_secret.federation_key(&config.global.calculate_federation_id())
    }

    /// Register to receiver all new transient (unpersisted) events
    pub fn get_event_log_transient_receiver(&self) -> broadcast::Receiver<EventLogEntry> {
        self.log_event_added_transient_tx.subscribe()
    }

    /// Check for pending config and migrate it if present.
    /// Returns the config to use (either the original or the migrated pending
    /// config).
    async fn migrate_pending_config_if_present(db: &Database) {
        if let Some(pending_config) = Client::get_pending_config_from_db(db).await {
            debug!(target: LOG_CLIENT, "Found pending client config, migrating to current config");

            let mut dbtx = db.begin_transaction().await;
            // Update the main config with the pending config
            dbtx.insert_entry(&crate::db::ClientConfigKey, &pending_config)
                .await;
            // Remove the pending config
            dbtx.remove_entry(&PendingClientConfigKey).await;
            dbtx.commit_tx().await;

            debug!(target: LOG_CLIENT, "Successfully migrated pending config to current config");
        }
    }

    /// Asynchronously refetch client config from federation and compare with
    /// existing. If different, save to pending config in database.
    fn load_and_refresh_client_config_static(
        config: &ClientConfig,
        api: &DynGlobalApi,
        db: &Database,
        task_group: &TaskGroup,
    ) {
        let config = config.clone();
        let api = api.clone();
        let db = db.clone();
        let task_group = task_group.clone();

        // Spawn background task to refetch config
        task_group.spawn_cancellable("refresh_client_config_static", async move {
            Self::refresh_client_config_static(&config, &api, &db).await;
        });
    }

    /// Wrapper that handles errors from config refresh with proper logging
    async fn refresh_client_config_static(
        config: &ClientConfig,
        api: &DynGlobalApi,
        db: &Database,
    ) {
        if let Err(error) = Self::refresh_client_config_static_try(config, api, db).await {
            warn!(
                target: LOG_CLIENT,
                err = %error.fmt_compact_anyhow(), "Failed to refresh client config"
            );
        }
    }

    /// Validate that a config update is valid
    fn validate_config_update(
        current_config: &ClientConfig,
        new_config: &ClientConfig,
    ) -> anyhow::Result<()> {
        // Global config must not change
        if current_config.global != new_config.global {
            bail!("Global configuration changes are not allowed in config updates");
        }

        // Modules can only be added, existing ones must stay the same
        for (module_id, current_module_config) in &current_config.modules {
            match new_config.modules.get(module_id) {
                Some(new_module_config) => {
                    if current_module_config != new_module_config {
                        bail!(
                            "Module {} configuration changes are not allowed, only additions are permitted",
                            module_id
                        );
                    }
                }
                None => {
                    bail!(
                        "Module {} was removed in new config, only additions are allowed",
                        module_id
                    );
                }
            }
        }

        Ok(())
    }

    /// Refetch client config from federation and save as pending if different
    async fn refresh_client_config_static_try(
        current_config: &ClientConfig,
        api: &DynGlobalApi,
        db: &Database,
    ) -> anyhow::Result<()> {
        debug!(target: LOG_CLIENT, "Refreshing client config");

        // Fetch latest config from federation
        let fetched_config = api
            .request_current_consensus::<ClientConfig>(
                CLIENT_CONFIG_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
            )
            .await?;

        // Validate the new config before proceeding
        Self::validate_config_update(current_config, &fetched_config)?;

        // Compare with current config
        if current_config != &fetched_config {
            debug!(target: LOG_CLIENT, "Detected federation config change, saving as pending config");

            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(&PendingClientConfigKey, &fetched_config)
                .await;
            dbtx.commit_tx().await;
        } else {
            debug!(target: LOG_CLIENT, "No federation config changes detected");
        }

        Ok(())
    }
}

pub struct ClientPreview {
    inner: ClientBuilder,
    config: ClientConfig,
    api_secret: Option<String>,
    prefetch_api_announcements: Option<Jit<Vec<anyhow::Result<PeersSignedApiAnnouncements>>>>,
    preview_prefetch_api_version_set:
        Option<JitTryAnyhow<BTreeMap<PeerId, SupportedApiVersionsSummary>>>,
}

impl ClientPreview {
    /// Get the config
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Join a new Federation
    ///
    /// When a user wants to connect to a new federation this function fetches
    /// the federation config and initializes the client database. If a user
    /// already joined the federation in the past and has a preexisting database
    /// use [`ClientBuilder::open`] instead.
    ///
    /// **Warning**: Calling `join` with a `root_secret` key that was used
    /// previous to `join` a Federation will lead to all sorts of malfunctions
    /// including likely loss of funds.
    ///
    /// This should be generally called only if the `root_secret` key is known
    /// not to have been used before (e.g. just randomly generated). For keys
    /// that might have been previous used (e.g. provided by the user),
    /// it's safer to call [`Self::recover`] which will attempt to recover
    /// client module states for the Federation.
    ///
    /// A typical "join federation" flow would look as follows:
    /// ```no_run
    /// # use std::str::FromStr;
    /// # use fedimint_core::invite_code::InviteCode;
    /// # use fedimint_core::config::ClientConfig;
    /// # use fedimint_derive_secret::DerivableSecret;
    /// # use fedimint_client::{Client, ClientBuilder, RootSecret};
    /// # use fedimint_core::db::Database;
    /// # use fedimint_core::config::META_FEDERATION_NAME_KEY;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// # let root_secret: DerivableSecret = unimplemented!();
    /// // Create a root secret, e.g. via fedimint-bip39, see also:
    /// // https://github.com/fedimint/fedimint/blob/master/docs/secret_derivation.md
    /// // let root_secret = …;
    ///
    /// // Get invite code from user
    /// let invite_code = InviteCode::from_str("fed11qgqpw9thwvaz7te3xgmjuvpwxqhrzw3jxumrvvf0qqqjpetvlg8glnpvzcufhffgzhv8m75f7y34ryk7suamh8x7zetly8h0v9v0rm")
    ///     .expect("Invalid invite code");
    ///
    /// // Tell the user the federation name, bitcoin network
    /// // (e.g. from wallet module config), and other details
    /// // that are typically contained in the federation's
    /// // meta fields.
    ///
    /// // let network = config.get_first_module_by_kind::<WalletClientConfig>("wallet")
    /// //     .expect("Module not found")
    /// //     .network;
    ///
    /// // Open the client's database, using the federation ID
    /// // as the DB name is a common pattern:
    ///
    /// // let db_path = format!("./path/to/db/{}", config.federation_id());
    /// // let db = RocksDb::open(db_path).expect("error opening DB");
    /// # let db: Database = unimplemented!();
    ///
    /// let preview = Client::builder().await
    ///     // Mount the modules the client should support:
    ///     // .with_module(LightningClientInit)
    ///     // .with_module(MintClientInit)
    ///     // .with_module(WalletClientInit::default())
    ///      .expect("Error building client")
    ///      .preview(&invite_code).await?;
    ///
    /// println!(
    ///     "The federation name is: {}",
    ///     preview.config().meta::<String>(META_FEDERATION_NAME_KEY)
    ///         .expect("Could not decode name field")
    ///         .expect("Name isn't set")
    /// );
    ///
    /// let client = preview
    ///     .join(db, RootSecret::StandardDoubleDerive(root_secret))
    ///     .await
    ///     .expect("Error joining federation");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn join(
        self,
        db_no_decoders: Database,
        pre_root_secret: RootSecret,
    ) -> anyhow::Result<ClientHandle> {
        let pre_root_secret = pre_root_secret.to_inner(self.config.calculate_federation_id());

        let client = self
            .inner
            .init(
                db_no_decoders,
                pre_root_secret,
                self.config,
                self.api_secret,
                InitMode::Fresh,
                self.prefetch_api_announcements,
                self.preview_prefetch_api_version_set,
            )
            .await?;

        Ok(client)
    }

    /// Join a (possibly) previous joined Federation
    ///
    /// Unlike [`Self::join`], `recover` will run client module
    /// recovery for each client module attempting to recover any previous
    /// module state.
    ///
    /// Recovery process takes time during which each recovering client module
    /// will not be available for use.
    ///
    /// Calling `recovery` with a `root_secret` that was not actually previous
    /// used in a given Federation is safe.
    pub async fn recover(
        self,
        db_no_decoders: Database,
        pre_root_secret: RootSecret,
        backup: Option<ClientBackup>,
    ) -> anyhow::Result<ClientHandle> {
        let pre_root_secret = pre_root_secret.to_inner(self.config.calculate_federation_id());

        let client = self
            .inner
            .init(
                db_no_decoders,
                pre_root_secret,
                self.config,
                self.api_secret,
                InitMode::Recover {
                    snapshot: backup.clone(),
                },
                self.prefetch_api_announcements,
                self.preview_prefetch_api_version_set,
            )
            .await?;

        Ok(client)
    }

    /// Download most recent valid backup found from the Federation
    pub async fn download_backup_from_federation(
        &self,
        pre_root_secret: RootSecret,
    ) -> anyhow::Result<Option<ClientBackup>> {
        let pre_root_secret = pre_root_secret.to_inner(self.config.calculate_federation_id());
        let api = DynGlobalApi::from_endpoints(
            // TODO: change join logic to use FederationId v2
            self.config
                .global
                .api_endpoints
                .iter()
                .map(|(peer_id, peer_url)| (*peer_id, peer_url.url.clone())),
            &self.api_secret,
            self.inner.iroh_enable_dht,
            self.inner.iroh_enable_next,
        )
        .await?;

        Client::download_backup_from_federation_static(
            &api,
            &ClientBuilder::federation_root_secret(&pre_root_secret, &self.config),
            &self.inner.decoders(&self.config),
        )
        .await
    }
}
