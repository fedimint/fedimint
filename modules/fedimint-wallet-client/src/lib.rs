pub mod api;

use bitcoin::Network;
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::ClientModule;
use fedimint_client::sm::{DynState, ModuleNotifier, OperationId, State, StateTransition};
use fedimint_client::{Client, DynGlobalClientContext};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_wallet_common::config::WalletClientConfig;
pub use fedimint_wallet_common::*;

pub trait WalletClientExt {
    fn get_network(&self) -> Network;
}

impl WalletClientExt for Client {
    fn get_network(&self) -> Network {
        let (wallet, _instance) = self.get_first_module::<WalletClientModule>(&KIND);
        wallet.get_network()
    }
}

#[derive(Debug, Clone)]
pub struct WalletClientGen;

impl ExtendsCommonModuleGen for WalletClientGen {
    type Common = WalletCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for WalletClientGen {
    type Module = WalletClientModule;
    type Config = WalletClientConfig;

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        _module_root_secret: DerivableSecret,
        _notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<Self::Module> {
        Ok(WalletClientModule { cfg })
    }
}

#[derive(Debug)]
pub struct WalletClientModule {
    cfg: WalletClientConfig,
}

impl ClientModule for WalletClientModule {
    type Common = WalletModuleTypes;
    type ModuleStateMachineContext = ();
    type States = WalletClientStates;

    fn context(&self) -> Self::ModuleStateMachineContext {}

    fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> TransactionItemAmount {
        unimplemented!()
    }

    fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        unimplemented!()
    }
}

impl WalletClientModule {
    fn get_network(&self) -> Network {
        self.cfg.network
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum WalletClientStates {}

impl IntoDynInstance for WalletClientStates {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for WalletClientStates {
    type ModuleContext = ();
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        unimplemented!()
    }

    fn operation_id(&self) -> OperationId {
        unimplemented!()
    }
}
