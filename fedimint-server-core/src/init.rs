// TODO: remove and fix nits
#![allow(clippy::pedantic)]

use std::collections::BTreeMap;
use std::marker;
use std::marker::PhantomData;
use std::sync::Arc;

use fedimint_core::config::{
    ClientModuleConfig, CommonModuleInitRegistry, ConfigGenModuleParams, ModuleInitParams,
    ModuleInitRegistry, ServerModuleConfig, ServerModuleConsensusConfig,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{CoreMigrationFn, Database, DatabaseVersion};
use fedimint_core::module::{
    CommonModuleInit, CoreConsensusVersion, IDynCommonModuleInit, ModuleConsensusVersion,
    ModuleInit, PeerHandle, SupportedModuleApiVersions,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define, NumPeers, PeerId};

use crate::DynServerModule;

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
    async fn init(
        &self,
        peer_num: NumPeers,
        cfg: ServerModuleConfig,
        db: Database,
        task_group: &TaskGroup,
        our_peer_id: PeerId,
    ) -> anyhow::Result<DynServerModule>;

    fn validate_params(&self, params: &ConfigGenModuleParams) -> anyhow::Result<()>;

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig>;

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
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
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, CoreMigrationFn>;
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
}
/// Module Generation trait with associated types
///
/// Needs to be implemented by module generation type
///
/// For examples, take a look at one of the `MintConfigGenerator`,
/// `WalletConfigGenerator`, or `LightningConfigGenerator` structs.
#[apply(async_trait_maybe_send!)]
pub trait ServerModuleInit: ModuleInit + Sized {
    type Params: ModuleInitParams;

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

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule>;

    fn parse_params(&self, params: &ConfigGenModuleParams) -> anyhow::Result<Self::Params> {
        params.to_typed::<Self::Params>()
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig>;

    async fn distributed_gen(
        &self,
        peer: &PeerHandle,
        params: &ConfigGenModuleParams,
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
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
        BTreeMap::new()
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
    ) -> anyhow::Result<DynServerModule> {
        <Self as ServerModuleInit>::init(
            self,
            &ServerModuleInitArgs {
                num_peers,
                cfg,
                db,
                task_group: task_group.clone(),
                our_peer_id,
                _marker: PhantomData,
            },
        )
        .await
    }

    fn validate_params(&self, params: &ConfigGenModuleParams) -> anyhow::Result<()> {
        <Self as ServerModuleInit>::parse_params(self, params)?;
        Ok(())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        <Self as ServerModuleInit>::trusted_dealer_gen(self, peers, params)
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> anyhow::Result<ServerModuleConfig> {
        <Self as ServerModuleInit>::distributed_gen(self, peers, params).await
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

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
        <Self as ServerModuleInit>::get_database_migrations(self)
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
}

impl ServerModuleInitRegistryExt for ServerModuleInitRegistry {
    fn to_common(&self) -> CommonModuleInitRegistry {
        self.iter().map(|(_k, v)| v.to_dyn_common()).collect()
    }
}
