use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::DatabaseTransaction;

/// A transaction that acts as isolated for module code but can be accessed as a
/// normal transaction in this crate.
pub struct ClientSMDatabaseTransaction<'inner, 'parent> {
    dbtx: &'inner mut DatabaseTransaction<'parent>,
    module_instance: ModuleInstanceId,
}

impl<'inner, 'parent> ClientSMDatabaseTransaction<'inner, 'parent> {
    pub fn new(
        dbtx: &'inner mut DatabaseTransaction<'parent>,
        module_instance: ModuleInstanceId,
    ) -> Self {
        Self {
            dbtx,
            module_instance,
        }
    }

    /// Returns the isolated database transaction for the module.
    pub fn module_tx(&mut self) -> DatabaseTransaction<'_> {
        self.dbtx
            .to_ref_with_prefix_module_id(self.module_instance)
            .into_non_committable()
    }

    /// Returns the non-isolated database transaction only accessible to the
    /// client internal code. This is useful for submitting Fedimint
    /// transactions from within state transitions.
    #[allow(dead_code)]
    pub(crate) fn global_tx(&mut self) -> &mut DatabaseTransaction<'parent> {
        self.dbtx
    }
}
