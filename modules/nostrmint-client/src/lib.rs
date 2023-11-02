use std::collections::HashMap;

use anyhow::anyhow;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::ClientModule;
use fedimint_client::sm::{Context, DynState, State};
use fedimint_client::{Client, DynGlobalClientContext};
use fedimint_core::api::DynModuleApi;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::ModuleDatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiAuth, ApiVersion, ExtendsCommonModuleInit, ModuleCommon, MultiApiVersion,
    TransactionItemAmount,
};
use fedimint_core::{apply, async_trait_maybe_send, PeerId};
use nostrmint_common::api::NostrmintFederationApi;
use nostrmint_common::{NostrmintCommonGen, NostrmintModuleTypes, UnsignedEvent, KIND};

#[apply(async_trait_maybe_send)]
pub trait NostrmintClientExt {
    async fn request_sign_event(
        &self,
        unsigned_event: nostr_sdk::UnsignedEvent,
        peer_id: PeerId,
        auth: ApiAuth,
    ) -> anyhow::Result<()>;
    async fn get_npub(&self) -> anyhow::Result<nostr_sdk::key::XOnlyPublicKey>;

    async fn list_note_requests(&self) -> anyhow::Result<HashMap<String, (UnsignedEvent, usize)>>;
}

#[apply(async_trait_maybe_send)]
impl NostrmintClientExt for Client {
    async fn request_sign_event(
        &self,
        unsigned_event: nostr_sdk::UnsignedEvent,
        peer_id: PeerId,
        auth: ApiAuth,
    ) -> anyhow::Result<()> {
        let (nostrmint, _instance) = self.get_first_module::<NostrmintClientModule>(&KIND);
        nostrmint
            .module_api
            .request_sign_event(UnsignedEvent(unsigned_event), peer_id, auth)
            .await?;
        Ok(())
    }

    async fn get_npub(&self) -> anyhow::Result<nostr_sdk::key::XOnlyPublicKey> {
        let (nostrmint, _instance) = self.get_first_module::<NostrmintClientModule>(&KIND);
        nostrmint
            .module_api
            .get_npub()
            .await
            .map_err(|e| anyhow!("get_npub error: {e:?}"))
    }

    async fn list_note_requests(&self) -> anyhow::Result<HashMap<String, (UnsignedEvent, usize)>> {
        let (nostrmint, _instance) = self.get_first_module::<NostrmintClientModule>(&KIND);
        nostrmint
            .module_api
            .list_note_requests()
            .await
            .map_err(|e| anyhow!("list_note_requests error: {e:?}"))
    }
}

#[derive(Debug, Clone)]
pub struct NostrmintClientGen;

#[apply(async_trait_maybe_send)]
impl ExtendsCommonModuleInit for NostrmintClientGen {
    type Common = NostrmintCommonGen;

    async fn dump_database(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(vec![].into_iter())
    }
}

#[apply(async_trait_maybe_send)]
impl ClientModuleInit for NostrmintClientGen {
    type Module = NostrmintClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(NostrmintClientModule {
            module_api: args.module_api().clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct NostrmintClientContext;

impl Context for NostrmintClientContext {}

#[derive(Debug)]
pub struct NostrmintClientModule {
    pub module_api: DynModuleApi,
}

impl ClientModule for NostrmintClientModule {
    type Common = NostrmintModuleTypes;
    type ModuleStateMachineContext = NostrmintClientContext;
    type States = NostrmintClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        NostrmintClientContext {}
    }

    fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> TransactionItemAmount {
        todo!()
    }

    fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        todo!()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum NostrmintClientStateMachines {}

impl IntoDynInstance for NostrmintClientStateMachines {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for NostrmintClientStateMachines {
    type ModuleContext = NostrmintClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        vec![]
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        todo!()
    }
}
