use std::any::Any;
use std::fmt::Debug;

use fedimint_core::core::{DynInput, DynModuleConsensusItem, DynOutput, ModuleInstanceId};
use fedimint_core::db::ModuleDatabaseTransaction;
use fedimint_core::encoding::{Decodable, DynEncodable, Encodable};
use fedimint_core::module::ModuleCommon;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, maybe_add_send_sync,
    module_plugin_dyn_newtype_clone_passthrough, module_plugin_dyn_newtype_define,
    module_plugin_dyn_newtype_encode_decode, module_plugin_dyn_newtype_eq_passthrough
};

use crate::module::{ClientModule, DynClientModule};
use crate::sm::DynState;
use crate::DynGlobalClientContext;

pub trait IModuleBackup: Debug + DynEncodable {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any));
    fn clone(&self, instance_id: ModuleInstanceId) -> DynModuleBackup;
    fn erased_eq_no_instance_id(&self, other: &DynModuleBackup) -> bool;
}

pub trait ModuleBackup:
    std::fmt::Debug
    + std::cmp::PartialEq
    + DynEncodable
    + Decodable
    + Clone
    + MaybeSend
    + MaybeSync
    + 'static
{
}

impl IModuleBackup for ::fedimint_core::core::DynUnknown {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any)) {
        self
    }

    fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> DynModuleBackup {
        DynModuleBackup::from_typed(instance_id, <Self as Clone>::clone(self))
    }

    fn erased_eq_no_instance_id(&self, other: &DynModuleBackup) -> bool {
        let other: &Self = other
            .as_any()
            .downcast_ref()
            .expect("Type is ensured in previous step");

        self == other
    }
}

impl<T> IModuleBackup for T
where
    T: ModuleBackup,
{
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any)) {
        self
    }

    fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> DynModuleBackup {
        DynModuleBackup::from_typed(instance_id, <Self as Clone>::clone(self))
    }

    fn erased_eq_no_instance_id(&self, other: &DynModuleBackup) -> bool {
        let other: &Self = other
            .as_any()
            .downcast_ref()
            .expect("Type is ensured in previous step");

        self == other
    }
}

module_plugin_dyn_newtype_define! {
    pub DynModuleBackup(Box<IModuleBackup>)
}

module_plugin_dyn_newtype_encode_decode!(DynModuleBackup);

module_plugin_dyn_newtype_clone_passthrough!(DynModuleBackup);

module_plugin_dyn_newtype_eq_passthrough!(DynModuleBackup);

impl ModuleBackup for () {}

#[apply(async_trait_maybe_send!)]
pub trait RecoveringModule:
    std::fmt::Debug
    + std::cmp::PartialEq
    + DynEncodable
    + Decodable
    + Clone
    + MaybeSend
    + MaybeSync
    + 'static
{
    type ClientModule: ClientModule;

    async fn process_ci(
        &mut self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        ci: <<Self::ClientModule as ClientModule>::Common as ModuleCommon>::ConsensusItem,
    );

    async fn process_input(
        &mut self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        input: <<Self::ClientModule as ClientModule>::Common as ModuleCommon>::Input,
    );

    async fn process_output(
        &mut self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        output: <<Self::ClientModule as ClientModule>::Common as ModuleCommon>::Output,
    );

    async fn finalize(
        self,
    ) -> (
        Self::ClientModule,
        Vec<<Self::ClientModule as ClientModule>::States>,
    );
}

#[apply(async_trait_maybe_send!)]
pub trait IRecoveringModule: Debug + DynEncodable {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any));
    fn clone(&self, instance_id: ModuleInstanceId) -> DynRecoveringModule;
    fn erased_eq_no_instance_id(&self, other: &DynRecoveringModule) -> bool;

    async fn process_ci(
        &mut self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        ci: DynModuleConsensusItem,
    );

    async fn process_input(&mut self, dbtx: &mut ModuleDatabaseTransaction<'_>, input: DynInput);

    async fn process_output(&mut self, dbtx: &mut ModuleDatabaseTransaction<'_>, output: DynOutput);

    async fn finalize(
        self,
        module_instance_id: ModuleInstanceId,
    ) -> (DynClientModule, Vec<DynState<DynGlobalClientContext>>);
}

#[apply(async_trait_maybe_send!)]
impl IRecoveringModule for ::fedimint_core::core::DynUnknown {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any)) {
        self
    }

    fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> DynRecoveringModule {
        DynRecoveringModule::from_typed(instance_id, <Self as Clone>::clone(self))
    }

    fn erased_eq_no_instance_id(&self, other: &DynRecoveringModule) -> bool {
        let other: &Self = other
            .as_any()
            .downcast_ref()
            .expect("Type is ensured in previous step");

        self == other
    }

    async fn process_ci(
        &mut self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _ci: DynModuleConsensusItem,
    ) {
        unimplemented!()
    }

    async fn process_input(&mut self, _dbtx: &mut ModuleDatabaseTransaction<'_>, _input: DynInput) {
        unimplemented!()
    }

    async fn process_output(
        &mut self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _output: DynOutput,
    ) {
        unimplemented!()
    }

    async fn finalize(
        self,
        _module_instance_id: ModuleInstanceId,
    ) -> (DynClientModule, Vec<DynState<DynGlobalClientContext>>) {
        unimplemented!()
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IRecoveringModule for T
where
    T: RecoveringModule,
{
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any)) {
        self
    }

    fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> DynRecoveringModule {
        DynRecoveringModule::from_typed(instance_id, <Self as Clone>::clone(self))
    }

    fn erased_eq_no_instance_id(&self, other: &DynRecoveringModule) -> bool {
        let other: &Self = other
            .as_any()
            .downcast_ref()
            .expect("Type is ensured in previous step");

        self == other
    }

    async fn process_ci(
        &mut self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        ci: DynModuleConsensusItem,
    ) {
        RecoveringModule::process_ci(
            self,
            dbtx,
            ci.as_any()
                .downcast_ref::<<<T::ClientModule as ClientModule>::Common as ModuleCommon>::ConsensusItem>()
                .expect("CI dispatched to wrong module")
                .clone(),
        )
        .await
    }

    async fn process_input(&mut self, dbtx: &mut ModuleDatabaseTransaction<'_>, input: DynInput) {
        RecoveringModule::process_input(
            self,
            dbtx,
            input
                .as_any()
                .downcast_ref::<<<T::ClientModule as ClientModule>::Common as ModuleCommon>::Input>(
                )
                .expect("Input dispatched to wrong module")
                .clone(),
        )
        .await
    }

    async fn process_output(
        &mut self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        output: DynOutput,
    ) {
        RecoveringModule::process_output(
            self,
            dbtx,
            output
                .as_any()
                .downcast_ref::<<<T::ClientModule as ClientModule>::Common as ModuleCommon>::Output>(
                )
                .expect("Output dispatched to wrong module")
                .clone(),
        ).await
    }

    async fn finalize(
        self,
        module_instance_id: ModuleInstanceId,
    ) -> (DynClientModule, Vec<DynState<DynGlobalClientContext>>) {
        let (client, states) = RecoveringModule::finalize(self).await;
        let dyn_client = DynClientModule::from(client);
        let dyn_states = states
            .into_iter()
            .map(|state| DynState::from_typed(module_instance_id, state))
            .collect();

        (dyn_client, dyn_states)
    }
}

module_plugin_dyn_newtype_define! {
    pub DynRecoveringModule(Box<IRecoveringModule>)
}

module_plugin_dyn_newtype_encode_decode!(DynRecoveringModule);

module_plugin_dyn_newtype_clone_passthrough!(DynRecoveringModule);

module_plugin_dyn_newtype_eq_passthrough!(DynRecoveringModule);
