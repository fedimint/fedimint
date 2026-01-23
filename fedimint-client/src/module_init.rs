use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use fedimint_api_client::api::DynGlobalApi;
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{
    BitcoindRpcNoChainIdFactory, ClientModuleInit, ClientModuleInitArgs, ClientModuleRecoverArgs,
};
use fedimint_client_module::module::recovery::{DynModuleBackup, RecoveryProgress};
use fedimint_client_module::module::{ClientContext, DynClientModule, FinalClientIface};
use fedimint_client_module::{ClientModule, ModuleInstanceId, ModuleKind};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::{ClientModuleConfig, FederationId, ModuleInitRegistry};
use fedimint_core::core::Decoder;
use fedimint_core::db::{Database, DatabaseVersion};
use fedimint_core::module::{
    ApiAuth, ApiVersion, CommonModuleInit, IDynCommonModuleInit, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::{MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::{NumPeers, apply, async_trait_maybe_send, dyn_newtype_define};
use fedimint_derive_secret::DerivableSecret;
use tokio::sync::watch;

use crate::sm::notifier::Notifier;

pub type ClientModuleInitRegistry = ModuleInitRegistry<DynClientModuleInit>;

#[apply(async_trait_maybe_send!)]
pub trait IClientModuleInit: IDynCommonModuleInit + fmt::Debug + MaybeSend + MaybeSync {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static);

    /// See [`ClientModuleInit::supported_api_versions`]
    fn supported_api_versions(&self) -> MultiApiVersion;

    #[allow(clippy::too_many_arguments)]
    async fn recover(
        &self,
        final_client: FinalClientIface,
        federation_id: FederationId,
        num_peers: NumPeers,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        core_api_version: ApiVersion,
        module_api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        notifier: Notifier,
        api: DynGlobalApi,
        admin_auth: Option<ApiAuth>,
        snapshot: Option<&DynModuleBackup>,
        progress_tx: watch::Sender<RecoveryProgress>,
        task_group: TaskGroup,
        user_bitcoind_rpc: Option<DynBitcoindRpc>,
        user_bitcoind_rpc_no_chain_id: Option<BitcoindRpcNoChainIdFactory>,
    ) -> anyhow::Result<()>;

    #[allow(clippy::too_many_arguments)]
    async fn init(
        &self,
        final_client: FinalClientIface,
        federation_id: FederationId,
        peer_num: usize,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        core_api_version: ApiVersion,
        module_api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        notifier: Notifier,
        api: DynGlobalApi,
        admin_auth: Option<ApiAuth>,
        task_group: TaskGroup,
        connector_registry: ConnectorRegistry,
        user_bitcoind_rpc: Option<DynBitcoindRpc>,
        user_bitcoind_rpc_no_chain_id: Option<BitcoindRpcNoChainIdFactory>,
    ) -> anyhow::Result<DynClientModule>;

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn>;

    /// See [`ClientModuleInit::used_db_prefixes`]
    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IClientModuleInit for T
where
    T: ClientModuleInit + 'static + MaybeSend + Sync,
{
    fn decoder(&self) -> Decoder {
        <<T as ClientModuleInit>::Module as ClientModule>::decoder()
    }

    fn module_kind(&self) -> ModuleKind {
        <Self as ModuleInit>::Common::KIND
    }

    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self
    }

    fn supported_api_versions(&self) -> MultiApiVersion {
        <Self as ClientModuleInit>::supported_api_versions(self)
    }

    async fn recover(
        &self,
        final_client: FinalClientIface,
        federation_id: FederationId,
        num_peers: NumPeers,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        core_api_version: ApiVersion,
        module_api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        // TODO: make dyn type for notifier
        notifier: Notifier,
        api: DynGlobalApi,
        admin_auth: Option<ApiAuth>,
        snapshot: Option<&DynModuleBackup>,
        progress_tx: watch::Sender<RecoveryProgress>,
        task_group: TaskGroup,
        user_bitcoind_rpc: Option<DynBitcoindRpc>,
        user_bitcoind_rpc_no_chain_id: Option<BitcoindRpcNoChainIdFactory>,
    ) -> anyhow::Result<()> {
        let typed_cfg: &<<T as fedimint_core::module::ModuleInit>::Common as CommonModuleInit>::ClientConfig = cfg.cast()?;
        let snapshot: Option<&<<Self as ClientModuleInit>::Module as ClientModule>::Backup> =
            snapshot.map(|s| {
                s.as_any()
                    .downcast_ref()
                    .expect("can't convert client module backup to desired type")
            });

        let (module_db, global_dbtx_access_token) = db.with_prefix_module_id(instance_id);
        Ok(<Self as ClientModuleInit>::recover(
            self,
            &ClientModuleRecoverArgs {
                federation_id,
                num_peers,
                cfg: typed_cfg.clone(),
                db: module_db.clone(),
                core_api_version,
                module_api_version,
                module_root_secret,
                notifier: notifier.module_notifier(instance_id, final_client.clone()),
                api: api.clone(),
                admin_auth,
                module_api: api.with_module(instance_id),
                context: ClientContext::new(
                    final_client,
                    instance_id,
                    global_dbtx_access_token,
                    module_db,
                ),
                progress_tx,
                task_group,
                user_bitcoind_rpc,
                user_bitcoind_rpc_no_chain_id,
            },
            snapshot,
        )
        .await?)
    }

    async fn init(
        &self,
        final_client: FinalClientIface,
        federation_id: FederationId,
        peer_num: usize,
        cfg: ClientModuleConfig,
        db: Database,
        instance_id: ModuleInstanceId,
        core_api_version: ApiVersion,
        module_api_version: ApiVersion,
        module_root_secret: DerivableSecret,
        // TODO: make dyn type for notifier
        notifier: Notifier,
        api: DynGlobalApi,
        admin_auth: Option<ApiAuth>,
        task_group: TaskGroup,
        connector_registry: ConnectorRegistry,
        user_bitcoind_rpc: Option<DynBitcoindRpc>,
        user_bitcoind_rpc_no_chain_id: Option<BitcoindRpcNoChainIdFactory>,
    ) -> anyhow::Result<DynClientModule> {
        let typed_cfg: &<<T as fedimint_core::module::ModuleInit>::Common as CommonModuleInit>::ClientConfig = cfg.cast()?;
        let (module_db, global_dbtx_access_token) = db.with_prefix_module_id(instance_id);
        Ok(<Self as ClientModuleInit>::init(
            self,
            &ClientModuleInitArgs {
                federation_id,
                peer_num,
                cfg: typed_cfg.clone(),
                db: module_db.clone(),
                core_api_version,
                module_api_version,
                module_root_secret,
                notifier: notifier.module_notifier(instance_id, final_client.clone()),
                api: api.clone(),
                admin_auth,
                module_api: api.with_module(instance_id),
                context: ClientContext::new(
                    final_client,
                    instance_id,
                    global_dbtx_access_token,
                    module_db,
                ),
                task_group,
                connector_registry,
                user_bitcoind_rpc,
                user_bitcoind_rpc_no_chain_id,
            },
        )
        .await?
        .into())
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        <Self as ClientModuleInit>::get_database_migrations(self)
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        <Self as ClientModuleInit>::used_db_prefixes(self)
    }
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynClientModuleInit(Arc<IClientModuleInit>)
);

impl AsRef<dyn IDynCommonModuleInit + Send + Sync + 'static> for DynClientModuleInit {
    fn as_ref(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self.inner.as_common()
    }
}

impl AsRef<dyn IClientModuleInit + 'static> for DynClientModuleInit {
    fn as_ref(&self) -> &(dyn IClientModuleInit + 'static) {
        self.inner.as_ref()
    }
}
