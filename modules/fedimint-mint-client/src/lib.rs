use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::ClientModule;
use fedimint_client::sm::{DynState, OperationId, State, StateTransition};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ExtendsCommonModuleGen;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_mint_common::config::MintClientConfig;
pub use fedimint_mint_common::*;

#[derive(Debug, Clone)]
pub struct MintClientGen;

impl ExtendsCommonModuleGen for MintClientGen {
    type Common = MintCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for MintClientGen {
    type Module = MintClientModule;
    type Config = MintClientConfig;

    async fn init(&self, _cfg: Self::Config, _db: Database) -> anyhow::Result<Self::Module> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct MintClientModule {}

impl ClientModule for MintClientModule {
    type Common = MintModuleTypes;
    type ModuleStateMachineContext = ();
    type GlobalStateMachineContext = ();
    type States = MintClientStates;

    fn context(&self) -> Self::ModuleStateMachineContext {
        unimplemented!()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum MintClientStates {}

impl IntoDynInstance for MintClientStates {
    type DynType = DynState<()>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State<()> for MintClientStates {
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
