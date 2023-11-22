use std::any::Any;
use std::fmt::Debug;

use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, DynEncodable, Encodable};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{
    maybe_add_send_sync, module_plugin_dyn_newtype_clone_passthrough,
    module_plugin_dyn_newtype_define, module_plugin_dyn_newtype_encode_decode,
    module_plugin_dyn_newtype_eq_passthrough,
};

pub trait IModuleBackup: Debug + DynEncodable {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any));
    fn clone(&self, instance_id: ModuleInstanceId) -> DynModuleBackup;
    fn erased_eq_no_instance_id(&self, other: &DynModuleBackup) -> bool;
}

pub trait ModuleBackup:
    std::fmt::Debug
    + IntoDynInstance<DynType = DynModuleBackup>
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

/// A backup type for modules without a backup implementation. The default
/// variant allows implementing a backup strategy for the module later on by
/// copying this enum into the module and adding a second variant to it.
#[derive(Clone, PartialEq, Eq, Debug, Encodable, Decodable)]
pub enum NoModuleBackup {
    NoModuleBackup,
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl ModuleBackup for NoModuleBackup {}

impl IntoDynInstance for NoModuleBackup {
    type DynType = DynModuleBackup;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleBackup::from_typed(instance_id, self)
    }
}
