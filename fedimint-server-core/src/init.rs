// TODO: remove and fix nits
#![allow(clippy::pedantic)]

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::Arc;
use std::{any, marker};

use bitcoin::Network;
use fedimint_api_client::api::DynModuleApi;
use fedimint_core::config::{
    ClientModuleConfig, CommonModuleInitRegistry, ModuleInitRegistry, ServerModuleConfig,
    ServerModuleConsensusConfig,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{Database, DatabaseVersion};
use fedimint_core::module::{
    CommonModuleInit, CoreConsensusVersion, IDynCommonModuleInit, ModuleConsensusVersion,
    ModuleInit, SupportedModuleApiVersions,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::{NumPeers, PeerId, apply, async_trait_maybe_send, dyn_newtype_define};

use crate::bitcoin_rpc::ServerBitcoinRpcMonitor;
use crate::config::PeerHandleOps;
use crate::migration::{
    DynServerDbMigrationFn, ServerDbMigrationFnContext, ServerModuleDbMigrationContext,
    ServerModuleDbMigrationFn,
};
use crate::{DynServerModule, ServerModule};

/// Arguments passed to modules during config generation
///
/// This replaces the per-module GenParams approach with a unified struct
/// containing all the information modules need for DKG/config generation.
#[derive(Debug, Clone, Copy)]
pub struct ConfigGenModuleArgs {
    /// Bitcoin network for the federation
    pub network: Network,
    /// Whether to disable base fees for this federation
    pub disable_base_fees: bool,
}

/// Interface for Module Generation
///
/// This trait contains the methods responsible for the module's
/// - initialization
/// - config generation
/// - config validation
///
/// Once the module configuration is ready, the module can be instantiated via
/// `[Self::init]`.
#[apply(async_trait_maybe_send!)]
pub trait IServerModuleInit: IDynCommonModuleInit {
    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static);

    fn supported_api_versions(&self) -> SupportedModuleApiVersions;

    /// Initialize the [`DynServerModule`] instance from its config
    #[allow(clippy::too_many_arguments)]
    async fn init(
        &self,
        peer_num: NumPeers,
        cfg: ServerModuleConfig,
        db: Database,
        task_group: &TaskGroup,
        our_peer_id: PeerId,
        module_api: DynModuleApi,
        server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor,
    ) -> anyhow::Result<DynServerModule>;

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig>;

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;

    fn get_client_config(
        &self,
        module_instance_id: ModuleInstanceId,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ClientModuleConfig>;

    /// Retrieves the migrations map from the server module to be applied to the
    /// database before the module is initialized. The migrations map is
    /// indexed on the from version.
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, DynServerDbMigrationFn>;

    /// See [`ServerModuleInit::used_db_prefixes`]
    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>>;

    /// Whether this module should be enabled by default in the setup UI
    fn is_enabled_by_default(&self) -> bool;
}

/// A type that can be used as module-shared value inside
/// [`ServerModuleInitArgs`]
pub trait ServerModuleShared: any::Any + Send + Sync {
    fn new(task_group: TaskGroup) -> Self;
}

pub struct ServerModuleInitArgs<S>
where
    S: ServerModuleInit,
{
    cfg: ServerModuleConfig,
    db: Database,
    task_group: TaskGroup,
    our_peer_id: PeerId,
    num_peers: NumPeers,
    module_api: DynModuleApi,
    server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor,
    // ClientModuleInitArgs needs a bound because sometimes we need
    // to pass associated-types data, so let's just put it here right away
    _marker: marker::PhantomData<S>,
}

impl<S> ServerModuleInitArgs<S>
where
    S: ServerModuleInit,
{
    pub fn cfg(&self) -> &ServerModuleConfig {
        &self.cfg
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn num_peers(&self) -> NumPeers {
        self.num_peers
    }

    pub fn task_group(&self) -> &TaskGroup {
        &self.task_group
    }

    pub fn our_peer_id(&self) -> PeerId {
        self.our_peer_id
    }

    pub fn module_api(&self) -> &DynModuleApi {
        &self.module_api
    }

    pub fn server_bitcoin_rpc_monitor(&self) -> ServerBitcoinRpcMonitor {
        self.server_bitcoin_rpc_monitor.clone()
    }
}
/// Module Generation trait with associated types
///
/// Needs to be implemented by module generation type
///
/// For examples, take a look at one of the `MintConfigGenerator`,
/// `WalletConfigGenerator`, or `LightningConfigGenerator` structs.
#[apply(async_trait_maybe_send!)]
pub trait ServerModuleInit: ModuleInit + Sized {
    type Module: ServerModule + Send + Sync;

    /// Version of the module consensus supported by this implementation given a
    /// certain [`CoreConsensusVersion`].
    ///
    /// Refer to [`ModuleConsensusVersion`] for more information about
    /// versioning.
    ///
    /// One module implementation ([`ServerModuleInit`] of a given
    /// [`ModuleKind`]) can potentially implement multiple versions of the
    /// consensus, and depending on the config module instance config,
    /// instantiate the desired one. This method should expose all the
    /// available versions, purely for information, setup UI and sanity
    /// checking purposes.
    fn versions(&self, core: CoreConsensusVersion) -> &[ModuleConsensusVersion];

    fn supported_api_versions(&self) -> SupportedModuleApiVersions;

    fn kind() -> ModuleKind {
        <Self as ModuleInit>::Common::KIND
    }

    /// Initialize the module instance from its config
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module>;

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig>;

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<<<Self as ModuleInit>::Common as CommonModuleInit>::ClientConfig>;

    /// Retrieves the migrations map from the server module to be applied to the
    /// database before the module is initialized. The migrations map is
    /// indexed on the from version.
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Self::Module>> {
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

    /// Whether this module should be enabled by default in the setup UI.
    /// Modules return `true` by default.
    fn is_enabled_by_default(&self) -> bool {
        true
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IServerModuleInit for T
where
    T: ServerModuleInit + 'static + Sync,
{
    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        <Self as ServerModuleInit>::supported_api_versions(self)
    }

    async fn init(
        &self,
        num_peers: NumPeers,
        cfg: ServerModuleConfig,
        db: Database,
        task_group: &TaskGroup,
        our_peer_id: PeerId,
        module_api: DynModuleApi,
        server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor,
    ) -> anyhow::Result<DynServerModule> {
        let module = <Self as ServerModuleInit>::init(
            self,
            &ServerModuleInitArgs {
                num_peers,
                cfg,
                db,
                task_group: task_group.clone(),
                our_peer_id,
                _marker: PhantomData,
                module_api,
                server_bitcoin_rpc_monitor,
            },
        )
        .await?;

        Ok(DynServerModule::from(module))
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        <Self as ServerModuleInit>::trusted_dealer_gen(self, peers, args)
    }

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        <Self as ServerModuleInit>::distributed_gen(self, peers, args).await
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        <Self as ServerModuleInit>::validate_config(self, identity, config)
    }

    fn get_client_config(
        &self,
        module_instance_id: ModuleInstanceId,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ClientModuleConfig> {
        ClientModuleConfig::from_typed(
            module_instance_id,
            <Self as ServerModuleInit>::kind(),
            config.version,
            <Self as ServerModuleInit>::get_client_config(self, config)?,
        )
    }
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, DynServerDbMigrationFn> {
        <Self as ServerModuleInit>::get_database_migrations(self)
            .into_iter()
            .map(|(k, f)| {
                (k, {
                    let closure: DynServerDbMigrationFn =
                        Box::new(move |ctx: ServerDbMigrationFnContext<'_>| {
                            let map = ctx.map(ServerModuleDbMigrationContext::new);
                            Box::pin(f(map))
                        });
                    closure
                })
            })
            .collect()
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        <Self as ServerModuleInit>::used_db_prefixes(self)
    }

    fn is_enabled_by_default(&self) -> bool {
        <Self as ServerModuleInit>::is_enabled_by_default(self)
    }
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynServerModuleInit(Arc<IServerModuleInit>)
);

impl AsRef<dyn IDynCommonModuleInit + Send + Sync + 'static> for DynServerModuleInit {
    fn as_ref(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self.inner.as_common()
    }
}

pub type ServerModuleInitRegistry = ModuleInitRegistry<DynServerModuleInit>;

pub trait ServerModuleInitRegistryExt {
    fn to_common(&self) -> CommonModuleInitRegistry;
    fn default_modules(&self) -> BTreeSet<ModuleKind>;
}

impl ServerModuleInitRegistryExt for ServerModuleInitRegistry {
    fn to_common(&self) -> CommonModuleInitRegistry {
        self.iter().map(|(_k, v)| v.to_dyn_common()).collect()
    }

    fn default_modules(&self) -> BTreeSet<ModuleKind> {
        self.iter()
            .filter(|(_kind, init)| init.is_enabled_by_default())
            .map(|(kind, _init)| kind.clone())
            .collect()
    }
}
