use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::WriteDatabaseTransaction;

/// A transaction that acts as isolated for module code but can be accessed as a
/// normal transaction in this crate.
pub struct ClientSMDatabaseTransaction<'inner, 'parent> {
    dbtx: &'inner mut WriteDatabaseTransaction<'parent>,
    module_instance: ModuleInstanceId,
}

impl<'inner, 'parent> ClientSMDatabaseTransaction<'inner, 'parent> {
    pub fn new(
        dbtx: &'inner mut WriteDatabaseTransaction<'parent>,
        module_instance: ModuleInstanceId,
    ) -> Self {
        Self {
            dbtx,
            module_instance,
        }
    }

    /// Returns the isolated database transaction for the module.
    pub fn module_tx(&mut self) -> WriteDatabaseTransaction<'_> {
        self.dbtx
            .to_ref_with_prefix_module_id(self.module_instance)
            .0
            .into_nc()
    }

    /// Returns the non-isolated database transaction only accessible to the
    /// client internal code. This is useful for submitting Fedimint
    /// transactions from within state transitions.
    // TODO: We don't want the client module to call this directly, ideally this
    // would be private, but after we've split fedimint-client-module and fedimint-client
    // we need to make it public.
    #[doc(hidden)]
    pub fn global_tx(&mut self) -> &mut WriteDatabaseTransaction<'parent> {
        self.dbtx
    }

    pub(crate) fn module_id(&self) -> ModuleInstanceId {
        self.module_instance
    }
}
