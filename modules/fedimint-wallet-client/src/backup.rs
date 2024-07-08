use fedimint_client::module::recovery::{DynModuleBackup, ModuleBackup};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};

use crate::client_db::TweakIdx;

#[derive(Clone, PartialEq, Eq, Debug, Encodable, Decodable)]
pub enum WalletModuleBackup {
    V0(WalletModuleBackupV0),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl IntoDynInstance for WalletModuleBackup {
    type DynType = DynModuleBackup;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleBackup::from_typed(instance_id, self)
    }
}

impl ModuleBackup for WalletModuleBackup {}

impl WalletModuleBackup {
    pub fn new_v0(next_tweak_idx: TweakIdx) -> WalletModuleBackup {
        WalletModuleBackup::V0(WalletModuleBackupV0 { next_tweak_idx })
    }
}
#[derive(Clone, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct WalletModuleBackupV0 {
    pub next_tweak_idx: TweakIdx,
}
