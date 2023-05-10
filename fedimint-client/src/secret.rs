use fedimint_core::core::ModuleInstanceId;
use fedimint_derive_secret::{ChildId, DerivableSecret};

const TYPE_MODULE: ChildId = ChildId(0);
const TYPE_BACKUP: ChildId = ChildId(1);

pub trait DeriveableSecretClientExt {
    fn derive_module_secret(&self, module_instance_id: ModuleInstanceId) -> DerivableSecret;
    fn derive_backup_secret(&self) -> DerivableSecret;
}

impl DeriveableSecretClientExt for DerivableSecret {
    fn derive_module_secret(&self, module_instance_id: ModuleInstanceId) -> DerivableSecret {
        assert_eq!(self.level(), 0);
        self.child_key(TYPE_MODULE)
            .child_key(ChildId(module_instance_id as u64))
    }

    fn derive_backup_secret(&self) -> DerivableSecret {
        assert_eq!(self.level(), 0);
        self.child_key(TYPE_BACKUP)
    }
}
