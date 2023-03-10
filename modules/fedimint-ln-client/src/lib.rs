use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::ClientModule;
use fedimint_client::sm::{DynState, OperationId, State, StateTransition};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ExtendsCommonModuleGen;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_ln_common::config::LightningClientConfig;
pub use fedimint_ln_common::*;

#[derive(Debug, Clone)]
pub struct LightningClientGen;

impl ExtendsCommonModuleGen for LightningClientGen {
    type Common = LightningCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for LightningClientGen {
    type Module = LightningClientModule;
    type Config = LightningClientConfig;

    async fn init(&self, _cfg: Self::Config, _db: Database) -> anyhow::Result<Self::Module> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct LightningClientModule {}

impl ClientModule for LightningClientModule {
    type Common = LightningModuleTypes;
    type ModuleStateMachineContext = ();
    type States = LightningClientStates;

    fn context(&self) -> Self::ModuleStateMachineContext {
        unimplemented!()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LightningClientStates {}

impl IntoDynInstance for LightningClientStates {
    type DynType = DynState<()>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State<()> for LightningClientStates {
    type ModuleContext = ();

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &(),
    ) -> Vec<StateTransition<Self>> {
        unimplemented!()
    }

    fn operation_id(&self) -> OperationId {
        unimplemented!()
    }
}
